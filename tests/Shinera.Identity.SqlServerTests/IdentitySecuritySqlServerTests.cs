using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Modules.System.Identity.Application.Services;
using Modules.System.Identity.Domain.Entities;
using Modules.System.Identity.Infrastructure.Persistence.Contexts;
using Modules.System.Identity.Web.Util;
using OpenIddict.Abstractions;
using Xunit;

namespace Shinera.Identity.SqlServerTests;

/// <summary>
/// Real SQL Server regression tests. They NEVER fall back to EF InMemory or SQLite.
/// Every test owns a fresh database, applies production migrations and deletes it.
/// The connection must point to an isolated disposable SQL Server with CREATE DATABASE permission.
/// </summary>
public sealed class IdentitySecuritySqlServerTests
{
    [Fact]
    public async Task Revoking_platform_role_blocks_refresh_and_stale_admin_access()
    {
        await WithIsolatedDatabaseAsync(async (db, _) =>
        {
            var systemScope = new Tenant(null, "Platform test scope", "system-test", "localhost");
            var user = NewUser(null, "test-admin", UserType.System);
            var role = new Role(systemScope.Id, "superadmin", "Platform role");
            var assignment = new UserRole(systemScope.Id, user.Id, role.Id);
            db.AddRange(systemScope, user, role, assignment);
            await db.SaveChangesAsync();

            var principal = Principal(user, "system", role: "superadmin");
            var validator = new RefreshGrantValidator(db);
            var requirement = new ActiveSystemAdministratorRequirement();
            var handler = new ActiveSystemAdministratorHandler(db);

            Assert.True(await validator.IsStillAuthorizedAsync(principal));
            Assert.True(await AuthorizedAsync(handler, requirement, principal));

            db.UserRoles.Remove(assignment);
            await db.SaveChangesAsync();

            Assert.False(await validator.IsStillAuthorizedAsync(principal));
            Assert.False(await AuthorizedAsync(handler, requirement, principal));

            // Revocation of account itself must also stop a previously issued token.
            user.IsActive = false;
            await db.SaveChangesAsync();
            Assert.False(await validator.IsStillAuthorizedAsync(principal));
        });
    }

    [Fact]
    public async Task Suspended_tenant_cannot_refresh_even_with_unchanged_claims()
    {
        await WithIsolatedDatabaseAsync(async (db, context) =>
        {
            var a = new Tenant(null, "Salon A", "salon-a", "localhost");
            var b = new Tenant(null, "Salon B", "salon-b", "localhost");
            var user = NewUser(a.Id, "tenant-user", UserType.Tenant);
            var roleA = new Role(a.Id, "staff", "Tenant A staff");
            var roleB = new Role(b.Id, "owner", "Tenant B owner");
            db.AddRange(a, b, user, roleA, roleB);
            await db.SaveChangesAsync();

            context.InitializeTenant(user.Id, a.Id, [a.Id], [a.Id], a.Id);
            db.ChangeTracker.Clear();

            var roleIds = await db.Roles.AsNoTracking().Select(x => x.Id).ToListAsync();
            Assert.Contains(roleA.Id, roleIds);
            Assert.DoesNotContain(roleB.Id, roleIds);

            var allRoleIds = await db.Roles.IgnoreQueryFilters(["tenant"])
                .AsNoTracking().Select(x => x.Id).ToListAsync();
            Assert.Contains(roleB.Id, allRoleIds); // Only an explicit, privileged bypass can cross scope.

            var principal = Principal(user, "tenant", tenantId: a.Id, slug: a.Slug);
            var validator = new RefreshGrantValidator(db);
            Assert.True(await validator.IsStillAuthorizedAsync(principal));

            a.IsActive = false;
            db.Tenants.Update(a);
            await db.SaveChangesAsync();
            Assert.False(await validator.IsStillAuthorizedAsync(principal));
        });
    }

    [Fact]
    public async Task Explicit_tenant_permission_enforces_resource_action_membership_and_revocation()
    {
        await WithIsolatedDatabaseAsync(async (db, _) =>
        {
            var tenantA = new Tenant(null, "Nail studio", "studio-a", "localhost");
            var tenantB = new Tenant(null, "Other business", "studio-b", "localhost");
            var user = NewUser(tenantA.Id, "permission-user", UserType.Tenant);
            var role = new Role(tenantA.Id, "receptionist", "Service viewer");
            var permission = new Permission
            {
                Code = "SERVICES.VIEW",
                Name = "services.view",
                IsActive = true
            };
            var membership = new UserRole(tenantA.Id, user.Id, role.Id);
            var grant = new RolePermission(tenantA.Id, role.Id, permission.Id);
            db.AddRange(tenantA, tenantB, user, role, permission, membership, grant);
            await db.SaveChangesAsync();

            var handler = new TenantPermissionHandler(db);
            var view = new TenantPermissionRequirement("services", "view");
            var delete = new TenantPermissionRequirement("services", "delete");
            var valid = Principal(user, "tenant", tenantId: tenantA.Id, slug: tenantA.Slug);

            Assert.True(await TenantPermissionAllowedAsync(handler, view, valid));
            Assert.False(await TenantPermissionAllowedAsync(handler, delete, valid));
            Assert.False(await TenantPermissionAllowedAsync(handler, view,
                Principal(user, "tenant", tenantId: tenantB.Id, slug: tenantB.Slug)));
            Assert.False(await TenantPermissionAllowedAsync(handler, view,
                Principal(user, "system", role: "superadmin")));

            db.RolePermissions.Remove(grant);
            await db.SaveChangesAsync();
            Assert.False(await TenantPermissionAllowedAsync(handler, view, valid));

            var direct = new UserPermission
            {
                TenantId = tenantA.Id, UserId = user.Id,
                PermissionId = permission.Id, IsGranted = true
            };
            db.UserPermissions.Add(direct);
            await db.SaveChangesAsync();
            Assert.True(await TenantPermissionAllowedAsync(handler, view, valid));

            tenantA.IsActive = false;
            await db.SaveChangesAsync();
            Assert.False(await TenantPermissionAllowedAsync(handler, view, valid));
        });
    }

    private static async Task<bool> TenantPermissionAllowedAsync(
        TenantPermissionHandler handler, TenantPermissionRequirement requirement,
        ClaimsPrincipal principal)
    {
        var authorization = new AuthorizationHandlerContext([requirement], principal, null);
        await handler.HandleAsync(authorization);
        return authorization.HasSucceeded;
    }

    [Fact]
    public async Task Tenant_group_grants_are_scoped_and_explicit_user_denial_overrides_inherited_role()
    {
        await WithIsolatedDatabaseAsync(async (db, _) =>
        {
            var tenantA = new Tenant(null, "Salon A", "group-tenant-a", "localhost");
            var tenantB = new Tenant(null, "Salon B", "group-tenant-b", "localhost");
            var user = NewUser(tenantA.Id, "group-user", UserType.Tenant);
            var role = new Role(tenantA.Id, "stylist", "Tenant A");
            var permission = new Permission
            {
                Code = "CUSTOMERS.VIEW",
                Name = "customers.view",
                IsActive = true
            };
            var group = new Group
            {
                TenantId = tenantA.Id,
                Name = "Team A",
                NormalizedName = "TEAM A"
            };
            var membership = new UserGroup
            {
                TenantId = tenantA.Id, UserId = user.Id, GroupId = group.Id
            };
            var groupRole = new GroupRole
            {
                TenantId = tenantA.Id, GroupId = group.Id, RoleId = role.Id
            };
            var rolePermission = new RolePermission(tenantA.Id, role.Id, permission.Id);

            db.AddRange(tenantA, tenantB, user, role, permission, group, membership,
                groupRole, rolePermission);
            await db.SaveChangesAsync();

            var principal = Principal(user, "tenant", tenantId: tenantA.Id, slug: tenantA.Slug);
            var requirement = new TenantPermissionRequirement("customers", "view");
            var handler = new TenantPermissionHandler(db);
            Assert.True(await TenantPermissionAllowedAsync(handler, requirement, principal));

            // Legacy user-level IsGranted=false semantics must not be bypassed by roles.
            var denial = new UserPermission
            {
                TenantId = tenantA.Id,
                UserId = user.Id,
                PermissionId = permission.Id,
                IsGranted = false
            };
            db.UserPermissions.Add(denial);
            await db.SaveChangesAsync();
            Assert.False(await TenantPermissionAllowedAsync(handler, requirement, principal));

            db.UserPermissions.Remove(denial);
            await db.SaveChangesAsync();
            Assert.True(await TenantPermissionAllowedAsync(handler, requirement, principal));

            // A corrupt cross-tenant GroupRole must never convey a permission.
            groupRole.TenantId = tenantB.Id;
            await db.SaveChangesAsync();
            Assert.False(await TenantPermissionAllowedAsync(handler, requirement, principal));
        });
    }

    private static User NewUser(Guid? tenantId, string username, UserType type)
        => new(tenantId, username, username + "@example.test", "Test", "User", type)
        {
            NormalizedUserName = username.ToUpperInvariant(),
            NormalizedEmail = (username + "@example.test").ToUpperInvariant(),
            PasswordHash = "CI-placeholder-not-used-for-login",
            SecurityStamp = "test-only-security-stamp"
        };

    private static ClaimsPrincipal Principal(
        User user, string accountType, Guid? tenantId = null, string? slug = null, string? role = null)
    {
        var claims = new List<Claim>
        {
            new(OpenIddictConstants.Claims.Subject, user.Id.ToString()),
            new("account_type", accountType),
            new("security_stamp", user.SecurityStamp!)
        };
        if (tenantId.HasValue)
        {
            claims.Add(new Claim("tenant_id", tenantId.Value.ToString()));
            claims.Add(new Claim("tenant", slug!));
        }
        if (role is not null)
            claims.Add(new Claim(OpenIddictConstants.Claims.Role, role));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
    }

    private static async Task<bool> AuthorizedAsync(
        ActiveSystemAdministratorHandler handler,
        ActiveSystemAdministratorRequirement requirement,
        ClaimsPrincipal principal)
    {
        var ctx = new AuthorizationHandlerContext([requirement], principal, null);
        await handler.HandleAsync(ctx);
        return ctx.HasSucceeded;
    }

    private static async Task WithIsolatedDatabaseAsync(Func<IdentityDbContext, TenantContext, Task> test)
    {
        var rawConnection = Environment.GetEnvironmentVariable("SHINERA_SQLSERVER_TEST_CONNECTION");
        if (string.IsNullOrWhiteSpace(rawConnection))
            throw new InvalidOperationException(
                "Set SHINERA_SQLSERVER_TEST_CONNECTION to an isolated SQL Server test instance.");

        var builder = new SqlConnectionStringBuilder(rawConnection)
        {
            InitialCatalog = "ShineraTest_" + Guid.NewGuid().ToString("N"),
            ConnectTimeout = 30
        };
        var tenantContext = new TenantContext();
        var options = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlServer(builder.ConnectionString, sql => sql.EnableRetryOnFailure())
            .Options;
        await using var db = new IdentityDbContext(options, tenantContext);
        try
        {
            // Exercise actual Identity migrations on SQL Server, not EnsureCreated.
            await db.Database.MigrateAsync();
            await test(db, tenantContext);
        }
        finally
        {
            await db.Database.EnsureDeletedAsync();
        }
    }
}
