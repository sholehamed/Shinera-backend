using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Modules.System.Identity.Domain.Entities;
using Modules.System.Identity.Infrastructure.Persistence;
using Modules.System.Identity.Infrastructure.Persistence.Contexts;
using Xunit;

namespace Shinera.Identity.SqlServerTests;

/// <summary>Real SQL Server + full migrations, no Production DB, EF fake or bypass.</summary>
public sealed class PlatformProductionGrantInventorySqlServerTests
{
    [Fact]
    public async Task Inventory_is_read_only_and_blocks_until_complete_reviewed_master_grants()
    {
        await WithDatabaseAsync(async db =>
        {
            var master = DefaultSeedData.MasterTenant.Id;
            db.Tenants.Add(new Tenant(master, null,
                "Platform", "readiness-master", "localhost"));
            var admin = NewUser(null, "readiness-admin", UserType.System);
            var role = new Role(master, "superadmin", "Test master role");
            db.AddRange(admin, role, new UserRole(master, admin.Id, role.Id));
            await db.SaveChangesAsync();

            // Definitions exist, but Product/Production startup must never
            // invent or automatically grant Master entitlements.
            await PlatformPermissionCatalogSeeder.SeedDefinitionsAsync(db);
            var before = await PlatformProductionGrantInventory.ReadAsync(db);
            Assert.True(before.MasterTenantActive);
            Assert.Equal(1, before.ActiveSuperAdminRoleCount);
            Assert.Equal(1, before.ActiveMasterSuperAdminAssignments);
            Assert.True(before.HasBlockingFindings);
            Assert.Equal(PlatformPermissionCatalog.Codes.Count,
                before.MissingSuperAdminGrantCodes.Count);
            Assert.Empty(before.MissingCatalogCodes);

            // Read-only inventory has not written a single authorization grant.
            Assert.Equal(0, await db.RolePermissions.IgnoreQueryFilters(["tenant"])
                .CountAsync(x => x.TenantId == master));
            var reportAgain = await PlatformProductionGrantInventory.ReadAsync(db);
            Assert.Equal(before.MissingSuperAdminGrantCodes.ToArray(),
                reportAgain.MissingSuperAdminGrantCodes.ToArray());
            Assert.Equal(before.ActiveMasterSuperAdminAssignments,
                reportAgain.ActiveMasterSuperAdminAssignments);

            var ids = await db.Permissions.AsNoTracking()
                .Where(x => PlatformPermissionCatalog.Codes.Contains(x.Code))
                .Select(x => x.Id).ToArrayAsync();
            foreach (var id in ids)
                db.RolePermissions.Add(new RolePermission(master, role.Id, id));
            await db.SaveChangesAsync();

            var complete = await PlatformProductionGrantInventory.ReadAsync(db);
            Assert.False(complete.HasBlockingFindings);
            Assert.Empty(complete.MissingSuperAdminGrantCodes);

            var toRemove = await db.RolePermissions.IgnoreQueryFilters(["tenant"])
                .FirstAsync(x => x.TenantId == master && x.RoleId == role.Id);
            db.RolePermissions.Remove(toRemove);
            await db.SaveChangesAsync();
            var incomplete = await PlatformProductionGrantInventory.ReadAsync(db);
            Assert.True(incomplete.HasBlockingFindings);
            Assert.Single(incomplete.MissingSuperAdminGrantCodes);
        });
    }

    [Fact]
    public async Task Inventory_detects_wrong_scope_and_explicit_system_user_denial()
    {
        await WithDatabaseAsync(async db =>
        {
            var master = DefaultSeedData.MasterTenant.Id;
            var tenant = new Tenant(null, "Foreign", "readiness-foreign", "localhost");
            db.AddRange(new Tenant(master, null, "Platform",
                "readiness-master", "localhost"), tenant);
            await db.SaveChangesAsync();

            var role = new Role(master, "superadmin", "Test");
            var admin = NewUser(null, "readiness-good", UserType.System);
            var tenantAccount = NewUser(tenant.Id, "readiness-tenant", UserType.Tenant);
            var systemWithTenant = NewUser(tenant.Id, "readiness-bad-system", UserType.System);
            db.AddRange(role, admin, tenantAccount, systemWithTenant,
                new UserRole(master, admin.Id, role.Id),
                new UserRole(master, tenantAccount.Id, role.Id));
            await db.SaveChangesAsync();
            await PlatformPermissionCatalogSeeder.SeedDefinitionsAsync(db);
            var codes = PlatformPermissionCatalog.Codes;
            var permissions = await db.Permissions.Where(x => codes.Contains(x.Code))
                .ToListAsync();
            foreach (var permission in permissions)
                db.RolePermissions.Add(new RolePermission(master, role.Id, permission.Id));

            db.UserPermissions.Add(new UserPermission
            {
                TenantId = master, UserId = admin.Id,
                PermissionId = permissions[0].Id, IsGranted = false
            });
            await db.SaveChangesAsync();

            var report = await PlatformProductionGrantInventory.ReadAsync(db);
            Assert.True(report.HasBlockingFindings);
            Assert.Equal(1, report.SystemUsersWithTenantId);
            Assert.Equal(1, report.InvalidMasterUserRoleAssignments);
            Assert.Equal(1, report.MasterCatalogUserDenials);
            Assert.Empty(report.MissingSuperAdminGrantCodes);
        });
    }

    private static User NewUser(Guid? tenantId, string name, UserType type)
        => new(tenantId, name, name + "@example.test", "Test", "User", type)
        {
            NormalizedUserName = name.ToUpperInvariant(),
            NormalizedEmail = (name + "@example.test").ToUpperInvariant(),
            PasswordHash = "CI-only-no-login",
            SecurityStamp = "CI-only-security-stamp"
        };

    private static async Task WithDatabaseAsync(Func<IdentityDbContext, Task> test)
    {
        var raw = Environment.GetEnvironmentVariable("SHINERA_SQLSERVER_TEST_CONNECTION");
        if (string.IsNullOrWhiteSpace(raw))
            throw new InvalidOperationException("Disposable SQL Server is required.");
        var connection = new SqlConnectionStringBuilder(raw)
        {
            InitialCatalog = "ShineraMasterInventory_" + Guid.NewGuid().ToString("N"),
            ConnectTimeout = 30
        };
        var options = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlServer(connection.ConnectionString).Options;
        await using var db = new IdentityDbContext(options, new TenantContext());
        try
        {
            await db.Database.MigrateAsync();
            await test(db);
        }
        finally
        {
            await db.Database.EnsureDeletedAsync();
        }
    }
}
