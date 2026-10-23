using System.Security.Claims;
using OpenIddict.Abstractions;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Modules.System.Identity.Web.Util;
using Modules.System.Identity.Application.Features.Roles.Commands;
using Modules.System.Identity.Application.Features.Groups.Commands;
using OpenIddict.Abstractions;
using System.Security.Claims;
using Modules.System.Identity.Application.Services;
using Modules.System.Identity.Domain.Entities;
using Modules.System.Identity.Infrastructure.Persistence;
using Modules.System.Identity.Infrastructure.Persistence.Contexts;
using Modules.System.Identity.Infrastructure.Persistence.Interceptors;
using Xunit;

namespace Shinera.Identity.SqlServerTests;

public sealed class TenantWriteIsolationSqlServerTests
{
    [Fact]
    public async Task Tenant_write_scope_allows_own_rows_and_rejects_cross_tenant_insert_update_delete()
    {
        await WithTestDatabaseAsync(async (setup, tenant, guard, trusted) =>
        {
            var a = new Tenant(null, "Tenant A", "write-a", "localhost");
            var b = new Tenant(null, "Tenant B", "write-b", "localhost");
            setup.AddRange(a, b);
            var roleB = new Role(b.Id, "foreign-role", "Must not be writable");
            setup.Roles.Add(roleB);
            await setup.SaveChangesAsync();

            tenant.InitializeTenant(Guid.NewGuid(), a.Id, [a.Id], [a.Id], a.Id);

            // Added records with no TenantId inherit the active authorized Tenant.
            var own = new Role(Guid.Empty, "own", "Allowed");
            guard.Roles.Add(own);
            await guard.SaveChangesAsync();
            Assert.Equal(a.Id, own.TenantId);

            // A read filter bypass does not grant a write bypass.
            using (tenant.DisableFilter())
            {
                guard.Roles.Add(new Role(b.Id, "foreign-added", null));
                await Assert.ThrowsAsync<UnauthorizedAccessException>(() => guard.SaveChangesAsync());
            }
            guard.ChangeTracker.Clear();

            var foreign = await guard.Roles.IgnoreQueryFilters(["tenant"])
                .SingleAsync(x => x.Id == roleB.Id);
            foreign.Description = "Attempted cross-tenant modification";
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => guard.SaveChangesAsync());
            guard.ChangeTracker.Clear();

            guard.Roles.Remove(await guard.Roles.IgnoreQueryFilters(["tenant"])
                .SingleAsync(x => x.Id == roleB.Id));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => guard.SaveChangesAsync());
            guard.ChangeTracker.Clear();

            // The synchronous SaveChanges path must receive the same guard.
            guard.Roles.Add(new Role(b.Id, "cross-sync", null));
            Assert.Throws<UnauthorizedAccessException>(() => guard.SaveChanges());
            guard.ChangeTracker.Clear();
        });
    }

    [Fact]
    public async Task Tenant_id_reassignment_is_denied_even_with_both_tenants_in_write_scope()
    {
        await WithTestDatabaseAsync(async (setup, tenant, guard, _) =>
        {
            var a = new Tenant(null, "Tenant A", "reassign-a", "localhost");
            var b = new Tenant(null, "Tenant B", "reassign-b", "localhost");
            var role = new Role(a.Id, "can-not-move", null);
            setup.AddRange(a, b, role);
            await setup.SaveChangesAsync();

            tenant.InitializeTenant(Guid.NewGuid(), a.Id, [a.Id, b.Id], [a.Id, b.Id], a.Id);
            var tracked = await guard.Roles.SingleAsync(x => x.Id == role.Id);
            tracked.TenantId = b.Id;
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => guard.SaveChangesAsync());
            guard.ChangeTracker.Clear();
        });
    }

    [Fact]
    public async Task Anonymous_and_unscoped_system_writes_fail_but_explicit_master_scope_is_bounded()
    {
        await WithTestDatabaseAsync(async (setup, tenant, guard, trusted) =>
        {
            var master = new Tenant(DefaultSeedData.MasterTenant.Id, null,
                "Platform", "platform-write-test", "localhost");
            var foreign = new Tenant(null, "Salon", "salon-write-test", "localhost");
            setup.AddRange(master, foreign);
            await setup.SaveChangesAsync();

            guard.Roles.Add(new Role(master.Id, "anonymous-forbidden", null));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => guard.SaveChangesAsync());
            guard.ChangeTracker.Clear();

            var actor = Guid.NewGuid();
            tenant.InitializeSystem(actor, isSuperAdmin: true);

            guard.Roles.Add(new Role(master.Id, "implicit-system-forbidden", null));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => guard.SaveChangesAsync());
            guard.ChangeTracker.Clear();

            Assert.Throws<UnauthorizedAccessException>(() =>
                trusted.BeginPlatformMasterWrite(tenant, Guid.NewGuid(), master.Id));
            Assert.Throws<UnauthorizedAccessException>(() =>
                trusted.BeginPlatformMasterWrite(tenant, actor, foreign.Id));

            using (trusted.BeginPlatformMasterWrite(tenant, actor, master.Id))
            {
                guard.Roles.Add(new Role(master.Id, "platform-allowed", null));
                await guard.SaveChangesAsync();

                guard.Roles.Add(new Role(foreign.Id, "platform-cross-tenant-forbidden", null));
                await Assert.ThrowsAsync<UnauthorizedAccessException>(() => guard.SaveChangesAsync());
            }
            guard.ChangeTracker.Clear();

            guard.Roles.Add(new Role(master.Id, "expired-platform-scope", null));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => guard.SaveChangesAsync());
            guard.ChangeTracker.Clear();
        });
    }

    [Fact]
    public async Task Bootstrap_scope_is_explicit_and_does_not_leak_after_disposal()
    {
        await WithTestDatabaseAsync(async (setup, tenant, guard, trusted) =>
        {
            var foreign = new Tenant(null, "Bootstrap tenant", "bootstrap-tenant", "localhost");
            setup.Tenants.Add(foreign);
            await setup.SaveChangesAsync();

            using (trusted.BeginBootstrapWrites())
            {
                guard.Roles.Add(new Role(foreign.Id, "seeded-role", null));
                await guard.SaveChangesAsync();
            }
            guard.ChangeTracker.Clear();

            guard.Roles.Add(new Role(foreign.Id, "outside-bootstrap", null));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => guard.SaveChangesAsync());
        });
    }

    [Fact]
    public async Task Platform_role_writer_allows_master_role_but_rejects_foreign_scope_and_revoked_actor()
    {
        await WithTestDatabaseAsync(async (setup, tenant, guarded, trusted) =>
        {
            var scope = DefaultSeedData.MasterTenant.Id;
            var master = new Tenant(scope, null, "Platform", "write-master", "localhost");
            var foreign = new Tenant(null, "Other salon", "write-foreign", "localhost");
            var actor = new User(null, "role-admin", "role-admin@example.test",
                "Platform", "Admin", UserType.System)
            {
                NormalizedUserName = "ROLE-ADMIN",
                NormalizedEmail = "ROLE-ADMIN@EXAMPLE.TEST",
                PasswordHash = "test-only",
                SecurityStamp = "test-stamp"
            };
            var superAdmin = new Role(scope, "superadmin", "Privileged System user");
            var membership = new UserRole(scope, actor.Id, superAdmin.Id);
            var foreignRole = new Role(foreign.Id, "foreign-role", null);
            setup.AddRange(master, foreign, actor, superAdmin, membership, foreignRole);
            await setup.SaveChangesAsync();

            tenant.InitializeSystem(actor.Id, isSuperAdmin: true);
            var principal = new ClaimsPrincipal(new ClaimsIdentity([
                new Claim(OpenIddictConstants.Claims.Subject, actor.Id.ToString()),
                new Claim("account_type", "system"),
                new Claim(OpenIddictConstants.Claims.Role, "superadmin")
            ], "test"));
            var writer = new PlatformRoleWriteExecutor(
                new AuthorizedPlatformMasterWrite(guarded, tenant, trusted,
                    NullLogger<AuthorizedPlatformMasterWrite>.Instance),
                guarded, trusted, NullLogger<PlatformRoleWriteExecutor>.Instance);

            var id = await writer.ExecuteAsync(principal, "roles.create", async () =>
            {
                var created = new Role(scope, "Platform editor", "Test role");
                guarded.Roles.Add(created);
                await guarded.SaveChangesAsync();
                return created.Id;
            });
            Assert.NotEqual(Guid.Empty, id);
            Assert.Equal(scope, (await guarded.Roles.IgnoreQueryFilters(["tenant"])
                .AsNoTracking().SingleAsync(x => x.Id == id)).TenantId);
            Assert.False(trusted.AllowsPlatformTenant(scope));

            // Trusted reads are not a privilege to mutate another tenant.
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => writer.ExecuteAsync(
                principal, "roles.update", () => Task.CompletedTask, foreignRole.Id));

            // A generic administrator Role CRUD endpoint may not forge the
            // name that is used for the live platform authorization decision.
            var mutationRan = false;
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => writer.ExecuteAsync(
                principal, "roles.create", () =>
                {
                    mutationRan = true;
                    return Task.CompletedTask;
                }, newRoleName: " superADMIN "));
            Assert.False(mutationRan);

            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => writer.ExecuteAsync(
                principal, "roles.update", () => Task.CompletedTask,
                id, newRoleName: "SUPERADMIN"));

            // Deleting, deactivating or replacing the grants of the existing
            // SuperAdmin role is a reviewed migration, not ordinary CRUD.
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => writer.ExecuteAsync(
                principal, "roles.delete", () => Task.CompletedTask, superAdmin.Id));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => writer.ExecuteAsync(
                principal, "roles.permissions.replace", () => Task.CompletedTask, superAdmin.Id));
            Assert.False(tenant.IsFilterDisabled);
            Assert.False(trusted.AllowsPlatformTenant(scope));

            // Revoked role membership invalidates a previously issued access token.
            setup.UserRoles.Remove(membership);
            await setup.SaveChangesAsync();
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => writer.ExecuteAsync(
                principal, "roles.create", () => Task.CompletedTask));
            Assert.False(trusted.AllowsPlatformTenant(scope));
        });
    }

    [Fact]
    public async Task Scoped_role_permission_assignment_is_atomic_and_cannot_target_foreign_role()
    {
        await WithTestDatabaseAsync(async (setup, tenant, guarded, trusted) =>
        {
            var scope = DefaultSeedData.MasterTenant.Id;
            var master = new Tenant(scope, null, "Platform", "permissions-master", "localhost");
            var foreign = new Tenant(null, "Other salon", "permissions-foreign", "localhost");
            var actor = new User(null, "permission-admin", "permission-admin@example.test",
                "Platform", "Admin", UserType.System)
            {
                NormalizedUserName = "PERMISSION-ADMIN",
                NormalizedEmail = "PERMISSION-ADMIN@EXAMPLE.TEST",
                PasswordHash = "test-only",
                SecurityStamp = "test-stamp"
            };
            var adminRole = new Role(scope, "superadmin", "Admin");
            var target = new Role(scope, "operator", "Managed");
            var otherRole = new Role(foreign.Id, "foreign", "Denied");
            var membership = new UserRole(scope, actor.Id, adminRole.Id);
            var permission = new Permission { Code = "ROLES.VIEW", Name = "roles.view" };
            setup.AddRange(master, foreign, actor, adminRole, target, otherRole,
                membership, permission);
            await setup.SaveChangesAsync();

            tenant.InitializeSystem(actor.Id, true);
            var principal = new ClaimsPrincipal(new ClaimsIdentity([
                new Claim(OpenIddictConstants.Claims.Subject, actor.Id.ToString()),
                new Claim("account_type", "system"),
                new Claim(OpenIddictConstants.Claims.Role, "superadmin")
            ], "test"));
            var writer = new PlatformRoleWriteExecutor(
                new AuthorizedPlatformMasterWrite(guarded, tenant, trusted,
                    NullLogger<AuthorizedPlatformMasterWrite>.Instance),
                guarded, trusted, NullLogger<PlatformRoleWriteExecutor>.Instance);

            var command = new UpdateRolePermissionsCommand
            {
                RoleId = target.Id,
                StorageTenantId = scope,
                PermissionIds = [permission.Id]
            };
            await writer.ExecuteAsync(principal, "roles.permissions.replace",
                async () => await new UpdateRolePermissionsCommandHandler(guarded)
                    .Handle(command, CancellationToken.None), target.Id);

            var applied = await guarded.RolePermissions.IgnoreQueryFilters(["tenant"])
                .AsNoTracking().SingleAsync(x => x.RoleId == target.Id);
            Assert.Equal(scope, applied.TenantId);
            Assert.Equal(permission.Id, applied.PermissionId);

            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => writer.ExecuteAsync(
                principal, "roles.permissions.replace", () => Task.CompletedTask, otherRole.Id));

            // No prior assignment must be lost if the request contains an invalid permission.
            command.PermissionIds = [Guid.NewGuid()];
            await Assert.ThrowsAnyAsync<Exception>(() => writer.ExecuteAsync(
                principal, "roles.permissions.replace",
                async () => await new UpdateRolePermissionsCommandHandler(guarded)
                    .Handle(command, CancellationToken.None), target.Id));

            Assert.Equal(permission.Id, (await guarded.RolePermissions.IgnoreQueryFilters(["tenant"])
                .AsNoTracking().SingleAsync(x => x.RoleId == target.Id)).PermissionId);
            Assert.False(trusted.AllowsPlatformTenant(scope));
        });
    }

    [Fact]
    public async Task Platform_master_write_requires_live_master_role_and_releases_scopes()
    {
        await WithTestDatabaseAsync(async (setup, tenant, guard, trusted) =>
        {
            var masterId = DefaultSeedData.MasterTenant.Id;
            var master = new Tenant(masterId, null, "Platform", "platform-scope-test", "localhost");
            var foreign = new Tenant(null, "Foreign tenant", "foreign-scope-test", "localhost");
            var actor = new User(null, "scope-admin", "scope-admin@example.test",
                "Scope", "Admin", UserType.System)
            {
                NormalizedUserName = "SCOPE-ADMIN",
                NormalizedEmail = "SCOPE-ADMIN@EXAMPLE.TEST",
                PasswordHash = "test-only",
                SecurityStamp = "test-security-stamp"
            };
            var role = new Role(masterId, "superadmin", "Platform admin");
            var membership = new UserRole(masterId, actor.Id, role.Id);
            setup.AddRange(master, foreign, actor, role, membership);
            await setup.SaveChangesAsync();

            tenant.InitializeSystem(actor.Id, isSuperAdmin: true);
            var principal = new ClaimsPrincipal(new ClaimsIdentity([
                new Claim(OpenIddictConstants.Claims.Subject, actor.Id.ToString()),
                new Claim("account_type", "system"),
                new Claim(OpenIddictConstants.Claims.Role, "superadmin")
            ], "test"));
            var access = new AuthorizedPlatformMasterWrite(guard, tenant, trusted,
                NullLogger<AuthorizedPlatformMasterWrite>.Instance);

            guard.Roles.Add(new Role(masterId, "outside-forbidden", null));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => guard.SaveChangesAsync());
            guard.ChangeTracker.Clear();

            using (await access.BeginAsync(principal))
            {
                var created = new Role(masterId, "platform-created", "Allowed only while scoped");
                guard.Roles.Add(created);
                await guard.SaveChangesAsync();
                Assert.Equal(masterId, created.TenantId);

                guard.Roles.Add(new Role(foreign.Id, "foreign-forbidden", null));
                await Assert.ThrowsAsync<UnauthorizedAccessException>(() => guard.SaveChangesAsync());
                guard.ChangeTracker.Clear();
            }

            Assert.False(tenant.IsFilterDisabled);
            guard.Roles.Add(new Role(masterId, "after-scope-forbidden", null));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => guard.SaveChangesAsync());
            guard.ChangeTracker.Clear();

            // A stale JWT and TenantContext claiming SuperAdmin cannot bypass
            // an actual role revocation in the persisted master definition scope.
            setup.UserRoles.Remove(membership);
            await setup.SaveChangesAsync();
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => access.BeginAsync(principal));
            Assert.False(tenant.IsFilterDisabled);

            // An account with an injected tenant-id claim is not System context.
            var forged = new ClaimsPrincipal(new ClaimsIdentity([
                new Claim(OpenIddictConstants.Claims.Subject, actor.Id.ToString()),
                new Claim("account_type", "system"),
                new Claim("tenant_id", foreign.Id.ToString()),
                new Claim(OpenIddictConstants.Claims.Role, "superadmin")
            ], "test"));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => access.BeginAsync(forged));
        });
    }


    [Fact]
    public async Task Permission_mutations_protect_platform_catalog_and_recheck_live_admin()
    {
        await WithTestDatabaseAsync(async (setup, tenant, guard, trusted) =>
        {
            var masterId = DefaultSeedData.MasterTenant.Id;
            var master = new Tenant(masterId, null, "Platform", "permission-guard-master", "localhost");
            var actor = new User(null, "permission-guard-admin", "permission-guard-admin@example.test",
                "Permission", "Admin", UserType.System)
            {
                NormalizedUserName = "PERMISSION-GUARD-ADMIN",
                NormalizedEmail = "PERMISSION-GUARD-ADMIN@EXAMPLE.TEST",
                PasswordHash = "test-only",
                SecurityStamp = "test-security-stamp"
            };
            var role = new Role(masterId, "superadmin", "Master operator");
            var membership = new UserRole(masterId, actor.Id, role.Id);
            var reserved = new Permission { Code = "ROLES.CREATE", Name = "System create Role" };
            var custom = new Permission { Code = "SERVICES.VIEW", Name = "Custom service view" };
            setup.AddRange(master, actor, role, membership, reserved, custom);
            await setup.SaveChangesAsync();

            tenant.InitializeSystem(actor.Id, isSuperAdmin: true);
            var principal = new ClaimsPrincipal(new ClaimsIdentity([
                new Claim(OpenIddictConstants.Claims.Subject, actor.Id.ToString()),
                new Claim("account_type", "system"),
                new Claim(OpenIddictConstants.Claims.Role, "superadmin")
            ], "test"));
            var gateway = new AuthorizedPlatformMasterWrite(guard, tenant, trusted,
                NullLogger<AuthorizedPlatformMasterWrite>.Instance);
            var writer = new PlatformPermissionWriteExecutor(gateway, guard,
                NullLogger<PlatformPermissionWriteExecutor>.Instance);

            var updated = await writer.ExecuteAsync(principal, "permissions.update", async () =>
            {
                var entry = await guard.Permissions.SingleAsync(x => x.Id == custom.Id);
                entry.Description = "Edited by verified platform operation";
                await guard.SaveChangesAsync();
                return entry.Id;
            }, permissionId: custom.Id);
            Assert.Equal(custom.Id, updated);
            Assert.False(tenant.IsFilterDisabled);
            Assert.False(trusted.AllowsPlatformTenant(masterId));

            // Catalog entries cannot be created, renamed, deleted or deactivated
            // through the general-purpose HTTP/CQRS administrative command path.
            var ran = false;
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => writer.ExecuteAsync(
                principal, "permissions.create",
                () => { ran = true; return Task.CompletedTask; },
                newCode: " roles.create "));
            Assert.False(ran);

            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => writer.ExecuteAsync(
                principal, "permissions.update", () => Task.CompletedTask,
                newCode: "SERVICES.VIEW", permissionId: reserved.Id));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => writer.ExecuteAsync(
                principal, "permissions.update", () => Task.CompletedTask,
                newCode: "permissions.delete", permissionId: custom.Id));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => writer.ExecuteAsync(
                principal, "permissions.change-state", () => Task.CompletedTask,
                permissionId: reserved.Id));
            Assert.False(tenant.IsFilterDisabled);

            setup.UserRoles.Remove(membership);
            await setup.SaveChangesAsync();
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => writer.ExecuteAsync(
                principal, "permissions.delete", () => Task.CompletedTask,
                permissionId: custom.Id));
            Assert.False(tenant.IsFilterDisabled);
        });
    }

    [Fact]
    public async Task Platform_group_membership_requires_live_admin_and_master_scoped_system_users()
    {
        await WithTestDatabaseAsync(async (setup, tenant, guard, trusted) =>
        {
            var masterId = DefaultSeedData.MasterTenant.Id;
            var master = new Tenant(masterId, null, "Platform", "group-members-master", "localhost");
            var foreign = new Tenant(null, "Tenant", "group-members-foreign", "localhost");
            var actor = new User(null, "group-admin", "group-admin@example.test",
                "Group", "Admin", UserType.System)
            {
                NormalizedUserName = "GROUP-ADMIN",
                NormalizedEmail = "GROUP-ADMIN@EXAMPLE.TEST",
                PasswordHash = "test-only", SecurityStamp = "test-only-stamp"
            };
            var member = new User(null, "group-member", "group-member@example.test",
                "Group", "Member", UserType.System)
            {
                NormalizedUserName = "GROUP-MEMBER",
                NormalizedEmail = "GROUP-MEMBER@EXAMPLE.TEST",
                PasswordHash = "test-only", SecurityStamp = "test-only-stamp"
            };
            var tenantUser = new User(foreign.Id, "tenant-member", "tenant-member@example.test",
                "Tenant", "Member", UserType.Tenant)
            {
                NormalizedUserName = "TENANT-MEMBER",
                NormalizedEmail = "TENANT-MEMBER@EXAMPLE.TEST",
                PasswordHash = "test-only", SecurityStamp = "test-only-stamp"
            };
            var superAdmin = new Role(masterId, "superadmin", "Privileged System role");
            var adminMembership = new UserRole(masterId, actor.Id, superAdmin.Id);
            var ordinaryGroup = new Group { TenantId = masterId, Name = "Operators", NormalizedName = "OPERATORS" };
            var privilegedGroup = new Group { TenantId = masterId, Name = "Administrators", NormalizedName = "ADMINISTRATORS" };
            var foreignGroup = new Group { TenantId = foreign.Id, Name = "Foreign", NormalizedName = "FOREIGN" };
            var privilegedLink = new GroupRole
            {
                TenantId = masterId, GroupId = privilegedGroup.Id, RoleId = superAdmin.Id
            };
            setup.AddRange(master, foreign, actor, member, tenantUser, superAdmin,
                adminMembership, ordinaryGroup, privilegedGroup, foreignGroup, privilegedLink);
            await setup.SaveChangesAsync();

            tenant.InitializeSystem(actor.Id, isSuperAdmin: true);
            var principal = new ClaimsPrincipal(new ClaimsIdentity([
                new Claim(OpenIddictConstants.Claims.Subject, actor.Id.ToString()),
                new Claim("account_type", "system"),
                new Claim(OpenIddictConstants.Claims.Role, "superadmin")
            ], "test"));
            var writer = new PlatformGroupMembershipWriteExecutor(
                new AuthorizedPlatformMasterWrite(guard, tenant, trusted,
                    NullLogger<AuthorizedPlatformMasterWrite>.Instance),
                guard, trusted, NullLogger<PlatformGroupMembershipWriteExecutor>.Instance);

            async Task AddMember(Guid groupId, Guid userId)
            {
                var command = new AddGroupMembersCommand
                {
                    StorageTenantId = masterId, GroupId = groupId, UserIds = [userId]
                };
                await writer.ExecuteAsync(principal, groupId, command.UserIds,
                    async () => await new AddGroupMembersCommandHandler(guard)
                        .Handle(command, CancellationToken.None));
            }

            await AddMember(ordinaryGroup.Id, member.Id);
            await AddMember(ordinaryGroup.Id, member.Id); // idempotent
            var stored = await guard.UserGroups.IgnoreQueryFilters(["tenant"])
                .AsNoTracking().Where(x => x.GroupId == ordinaryGroup.Id).ToListAsync();
            Assert.Single(stored);
            Assert.Equal(masterId, stored[0].TenantId);
            Assert.Equal(member.Id, stored[0].UserId);

            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                AddMember(foreignGroup.Id, member.Id));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                AddMember(ordinaryGroup.Id, tenantUser.Id));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                AddMember(privilegedGroup.Id, member.Id));
            Assert.False(tenant.IsFilterDisabled);
            Assert.False(trusted.AllowsPlatformTenant(masterId));

            setup.UserRoles.Remove(adminMembership);
            await setup.SaveChangesAsync();
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                AddMember(ordinaryGroup.Id, actor.Id));
            Assert.False(trusted.AllowsPlatformTenant(masterId));
        });
    }


    [Fact]
    public async Task Platform_master_write_requires_explicit_target_grant_intent()
    {
        await WithTestDatabaseAsync(async (setup, tenant, guard, trusted) =>
        {
            var masterId = DefaultSeedData.MasterTenant.Id;
            var master = new Tenant(masterId, null, "Platform", "grant-scope-master", "localhost");
            var actor = new User(null, "grant-admin", "grant-admin@example.test",
                "Grant", "Admin", UserType.System)
            {
                NormalizedUserName = "GRANT-ADMIN",
                NormalizedEmail = "GRANT-ADMIN@EXAMPLE.TEST",
                PasswordHash = "test-only", SecurityStamp = "test-grant-stamp"
            };
            var super = new Role(masterId, "superadmin", "Root administrator");
            var operatorRole = new Role(masterId, "operator", "Nonprivileged role");
            var otherRole = new Role(masterId, "auditor", "Other role");
            var group = new Group { TenantId = masterId, Name = "Operators", NormalizedName = "OPERATORS" };
            var otherGroup = new Group { TenantId = masterId, Name = "Auditors", NormalizedName = "AUDITORS" };
            var membership = new UserRole(masterId, actor.Id, super.Id);
            var permission = new Permission { Code = "REPORTS.VIEW", Name = "View reports", IsActive = true };
            setup.AddRange(master, actor, super, operatorRole, otherRole,
                group, otherGroup, membership, permission);
            await setup.SaveChangesAsync();

            tenant.InitializeSystem(actor.Id, isSuperAdmin: true);
            var principal = new ClaimsPrincipal(new ClaimsIdentity([
                new Claim(OpenIddictConstants.Claims.Subject, actor.Id.ToString()),
                new Claim("account_type", "system"),
                new Claim(OpenIddictConstants.Claims.Role, "superadmin")
            ], "test"));
            var gateway = new AuthorizedPlatformMasterWrite(guard, tenant, trusted,
                NullLogger<AuthorizedPlatformMasterWrite>.Instance);
            var roleWriter = new PlatformRoleWriteExecutor(gateway, guard, trusted,
                NullLogger<PlatformRoleWriteExecutor>.Instance);
            var groupWriter = new PlatformGroupMembershipWriteExecutor(gateway, guard, trusted,
                NullLogger<PlatformGroupMembershipWriteExecutor>.Instance);

            async Task DeniedSaveAsync(Action stage)
            {
                stage();
                await Assert.ThrowsAsync<UnauthorizedAccessException>(() => guard.SaveChangesAsync());
                guard.ChangeTracker.Clear();
            }

            // A validated platform administrator does not receive blanket
            // authority to assign roles, group roles, direct user permissions,
            // or even role permissions without a target-specific intent.
            using (await gateway.BeginAsync(principal))
            {
                await DeniedSaveAsync(() => guard.UserRoles.Add(
                    new UserRole(masterId, actor.Id, operatorRole.Id)));
                await DeniedSaveAsync(() => guard.GroupRoles.Add(new GroupRole
                {
                    TenantId = masterId, GroupId = group.Id, RoleId = operatorRole.Id
                }));
                await DeniedSaveAsync(() => guard.UserPermissions.Add(new UserPermission
                {
                    TenantId = masterId, UserId = actor.Id, PermissionId = permission.Id
                }));
                await DeniedSaveAsync(() => guard.RolePermissions.Add(
                    new RolePermission(masterId, operatorRole.Id, permission.Id)));
                await DeniedSaveAsync(() => guard.UserGroups.Add(new UserGroup
                {
                    TenantId = masterId, UserId = actor.Id, GroupId = group.Id
                }));
            }

            // Even an authorized RolePermission operation cannot target a
            // different role or smuggle unrelated grant types into SaveChanges.
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                roleWriter.ExecuteAsync(principal, "roles.permissions.replace",
                    async () =>
                    {
                        guard.RolePermissions.Add(new RolePermission(masterId,
                            otherRole.Id, permission.Id));
                        await guard.SaveChangesAsync();
                    }, operatorRole.Id));
            guard.ChangeTracker.Clear();

            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                roleWriter.ExecuteAsync(principal, "roles.permissions.replace",
                    async () =>
                    {
                        guard.UserRoles.Add(new UserRole(masterId, actor.Id, operatorRole.Id));
                        await guard.SaveChangesAsync();
                    }, operatorRole.Id));
            guard.ChangeTracker.Clear();

            // Validated GroupMember mutations cannot modify another group or
            // create a direct UserRole in the same trusted write operation.
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                groupWriter.ExecuteAsync(principal, group.Id, [actor.Id], async () =>
                {
                    guard.UserGroups.Add(new UserGroup
                    {
                        TenantId = masterId, UserId = actor.Id, GroupId = otherGroup.Id
                    });
                    await guard.SaveChangesAsync();
                }));
            guard.ChangeTracker.Clear();

            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                groupWriter.ExecuteAsync(principal, group.Id, [actor.Id], async () =>
                {
                    guard.UserRoles.Add(new UserRole(masterId, actor.Id, operatorRole.Id));
                    await guard.SaveChangesAsync();
                }));
            guard.ChangeTracker.Clear();

            Assert.False(tenant.IsFilterDisabled);
            Assert.False(trusted.AllowsPlatformTenant(masterId));
        });
    }


    [Fact]
    public async Task Direct_platform_user_role_grants_are_scoped_idempotent_and_revocable()
    {
        await WithTestDatabaseAsync(async (setup, tenant, guarded, trusted) =>
        {
            var masterId = DefaultSeedData.MasterTenant.Id;
            var master = new Tenant(masterId, null, "Platform", "direct-grant-master", "localhost");
            var foreign = new Tenant(null, "Tenant", "direct-grant-tenant", "localhost");
            var admin = new User(null, "direct-admin", "direct-admin@example.test",
                "Direct", "Admin", UserType.System)
            {
                NormalizedUserName = "DIRECT-ADMIN", NormalizedEmail = "DIRECT-ADMIN@EXAMPLE.TEST",
                PasswordHash = "test-only", SecurityStamp = "test-only"
            };
            var systemUser = new User(null, "direct-user", "direct-user@example.test",
                "Direct", "User", UserType.System)
            {
                NormalizedUserName = "DIRECT-USER", NormalizedEmail = "DIRECT-USER@EXAMPLE.TEST",
                PasswordHash = "test-only", SecurityStamp = "test-only"
            };
            var tenantUser = new User(foreign.Id, "direct-tenant", "direct-tenant@example.test",
                "Tenant", "User", UserType.Tenant)
            {
                NormalizedUserName = "DIRECT-TENANT", NormalizedEmail = "DIRECT-TENANT@EXAMPLE.TEST",
                PasswordHash = "test-only", SecurityStamp = "test-only"
            };
            var superAdmin = new Role(masterId, "superadmin", "Bootstrap role");
            var operatorRole = new Role(masterId, "operator", "Nonprivileged role");
            var foreignRole = new Role(foreign.Id, "foreign-role", "Foreign role");
            var adminMembership = new UserRole(masterId, admin.Id, superAdmin.Id);
            setup.AddRange(master, foreign, admin, systemUser, tenantUser,
                superAdmin, operatorRole, foreignRole, adminMembership);
            await setup.SaveChangesAsync();

            tenant.InitializeSystem(admin.Id, isSuperAdmin: true);
            var principal = new ClaimsPrincipal(new ClaimsIdentity([
                new Claim(OpenIddictConstants.Claims.Subject, admin.Id.ToString()),
                new Claim("account_type", "system"),
                new Claim(OpenIddictConstants.Claims.Role, "superadmin")
            ], "test"));
            var gateway = new AuthorizedPlatformMasterWrite(guarded, tenant, trusted,
                NullLogger<AuthorizedPlatformMasterWrite>.Instance);
            var service = new PlatformUserRoleWriteService(guarded, gateway, trusted,
                NullLogger<PlatformUserRoleWriteService>.Instance);

            // Indefinite lockout is not a valid target for a new grant.
            systemUser.IsLockedOut = true;
            systemUser.LockoutEndUtc = null;
            await setup.SaveChangesAsync();
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                service.ChangeAsync(principal, systemUser.Id, operatorRole.Id, true));
            systemUser.IsLockedOut = false;
            await setup.SaveChangesAsync();

            // Unrelated tracked role-grants cannot piggyback on the allowed
            // UserRole mutation or be committed as part of the same SaveChanges.
            var group = new Group
            {
                TenantId = masterId, Name = "Reviewers", NormalizedName = "REVIEWERS"
            };
            setup.Groups.Add(group);
            await setup.SaveChangesAsync();
            guarded.GroupRoles.Add(new GroupRole
            {
                TenantId = masterId, GroupId = group.Id, RoleId = operatorRole.Id
            });
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                service.ChangeAsync(principal, systemUser.Id, operatorRole.Id, true));
            guarded.ChangeTracker.Clear();
            Assert.Empty(await guarded.UserRoles.IgnoreQueryFilters(["tenant"])
                .AsNoTracking().Where(x => x.UserId == systemUser.Id).ToListAsync());

            Assert.True(await service.ChangeAsync(principal, systemUser.Id, operatorRole.Id, true));
            Assert.False(await service.ChangeAsync(principal, systemUser.Id, operatorRole.Id, true));
            Assert.Single(await guarded.UserRoles.IgnoreQueryFilters(["tenant"])
                .AsNoTracking().Where(x => x.UserId == systemUser.Id).ToListAsync());
            Assert.False(tenant.IsFilterDisabled);
            Assert.False(trusted.AllowsPlatformTenant(masterId));

            // Explicitly disallow self-grants, privilege escalation,
            // tenant-user targets and roles from a foreign storage tenant.
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                service.ChangeAsync(principal, admin.Id, operatorRole.Id, true));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                service.ChangeAsync(principal, systemUser.Id, superAdmin.Id, true));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                service.ChangeAsync(principal, tenantUser.Id, operatorRole.Id, true));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                service.ChangeAsync(principal, systemUser.Id, foreignRole.Id, true));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                service.ChangeAsync(principal, systemUser.Id, foreignRole.Id, false));

            // No denied request can silently remove a previously valid grant.
            Assert.Single(await guarded.UserRoles.IgnoreQueryFilters(["tenant"])
                .AsNoTracking().Where(x => x.UserId == systemUser.Id).ToListAsync());

            Assert.True(await service.ChangeAsync(principal, systemUser.Id, operatorRole.Id, false));
            Assert.False(await service.ChangeAsync(principal, systemUser.Id, operatorRole.Id, false));
            Assert.Empty(await guarded.UserRoles.IgnoreQueryFilters(["tenant"])
                .AsNoTracking().Where(x => x.UserId == systemUser.Id).ToListAsync());

            // Admin authorization is rechecked on the live database for every
            // grant; a stale JWT cannot keep granting after role revocation.
            setup.UserRoles.Remove(adminMembership);
            await setup.SaveChangesAsync();
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                service.ChangeAsync(principal, systemUser.Id, operatorRole.Id, true));
            Assert.False(tenant.IsFilterDisabled);
            Assert.False(trusted.AllowsPlatformTenant(masterId));
        });
    }

    private static async Task WithTestDatabaseAsync(
        Func<IdentityDbContext, TenantContext, IdentityDbContext, TrustedTenantWriteScope, Task> test)
    {
        var connection = Environment.GetEnvironmentVariable("SHINERA_SQLSERVER_TEST_CONNECTION");
        if (string.IsNullOrWhiteSpace(connection))
            throw new InvalidOperationException("SHINERA_SQLSERVER_TEST_CONNECTION is required");

        var cs = new SqlConnectionStringBuilder(connection)
        {
            InitialCatalog = "ShineraWriteTest_" + Guid.NewGuid().ToString("N"),
            ConnectTimeout = 30
        };

        var tenant = new TenantContext();
        var setupOptions = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlServer(cs.ConnectionString, sql => sql.EnableRetryOnFailure())
            .Options;

        await using var setup = new IdentityDbContext(setupOptions, tenant);
        var trusted = new TrustedTenantWriteScope(NullLogger<TrustedTenantWriteScope>.Instance);
        var interceptor = new TenantSaveChangesInterceptor(tenant, trusted);
        var guardedOptions = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlServer(cs.ConnectionString, sql => sql.EnableRetryOnFailure())
            .AddInterceptors(interceptor).Options;

        try
        {
            await setup.Database.MigrateAsync();
            await using var guarded = new IdentityDbContext(guardedOptions, tenant);
            await test(setup, tenant, guarded, trusted);
        }
        finally
        {
            await setup.Database.EnsureDeletedAsync();
        }
    }
}
