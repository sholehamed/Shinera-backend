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
