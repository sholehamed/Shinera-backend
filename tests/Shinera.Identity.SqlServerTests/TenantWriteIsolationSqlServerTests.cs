using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Modules.System.Identity.Web.Util;
using Modules.System.Identity.Application.Features.Roles.Commands;
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
            var writer = new PlatformRoleWriteExecutor(guarded, tenant, trusted,
                NullLogger<PlatformRoleWriteExecutor>.Instance);

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
            var writer = new PlatformRoleWriteExecutor(guarded, tenant, trusted,
                NullLogger<PlatformRoleWriteExecutor>.Instance);

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
