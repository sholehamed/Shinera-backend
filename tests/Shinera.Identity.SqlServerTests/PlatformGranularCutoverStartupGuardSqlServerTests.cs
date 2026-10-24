using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Modules.System.Identity.Domain.Entities;
using Modules.System.Identity.Infrastructure.Persistence;
using Modules.System.Identity.Infrastructure.Persistence.Contexts;
using Xunit;

namespace Shinera.Identity.SqlServerTests;

/// <summary>
/// Real, disposable SQL Server Production-startup interlock regressions.
/// No test connects to an actual customer database or flips Production flags.
/// </summary>
public sealed class PlatformGranularCutoverStartupGuardSqlServerTests
{
    [Fact]
    public async Task Production_off_is_safe_and_enable_without_review_is_denied()
    {
        await WithDatabaseAsync(async (db, name) =>
        {
            await PlatformGranularCutoverStartupGuard.ValidateAsync(db,
                Config(false, false), isProduction: true);
            await PlatformGranularCutoverStartupGuard.ValidateAsync(db,
                Config(true, true), isProduction: false); // CI/dev opt-in unchanged

            // Exact flags alone MUST NOT turn on the Production authorization
            // overlay, even if catalog/grants happen to be populated.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                PlatformGranularCutoverStartupGuard.ValidateAsync(db,
                    Config(true, false), isProduction: true));
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                PlatformGranularCutoverStartupGuard.ValidateAsync(db,
                    Config(false, true), isProduction: true));

            // Acknowledging a different database is a deployment mistake.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                PlatformGranularCutoverStartupGuard.ValidateAsync(db,
                    Config(true, false, "other-production-db"), isProduction: true));
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                PlatformGranularCutoverStartupGuard.ValidateAsync(db,
                    Config(true, false, name, Guid.NewGuid()),
                    isProduction: true));

            // An acknowledgement without any live Master grants remains
            // blocked by the read-only 5A inventory.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                PlatformGranularCutoverStartupGuard.ValidateAsync(db,
                    Config(true, false, name), isProduction: true));
        });
    }

    [Fact]
    public async Task Reviewed_complete_master_grants_allow_preflight_only_and_revoke_reblocks()
    {
        await WithDatabaseAsync(async (db, name) =>
        {
            var master = DefaultSeedData.MasterTenant.Id;
            db.Tenants.Add(new Tenant(master, null,
                "Master", "cutover-reviewed-master", "localhost"));
            var role = new Role(master, "superadmin", "CI-only platform");
            var system = new User(null, "cutover-admin",
                "cutover-admin@localhost.test", "CI", "Admin", UserType.System)
            {
                NormalizedUserName = "CUTOVER-ADMIN",
                NormalizedEmail = "CUTOVER-ADMIN@LOCALHOST.TEST",
                PasswordHash = "CI-only",
                SecurityStamp = "CI-only"
            };
            db.AddRange(role, system, new UserRole(master, system.Id, role.Id));
            await db.SaveChangesAsync();
            await PlatformPermissionCatalogSeeder.SeedDefinitionsAsync(db);
            var codes = PlatformPermissionCatalog.Codes;
            var catalog = await db.Permissions.AsNoTracking()
                .Where(p => codes.Contains(p.Code)).ToListAsync();
            foreach (var p in catalog)
                db.RolePermissions.Add(new RolePermission(master, role.Id, p.Id));
            await db.SaveChangesAsync();

            var grantsBefore = await db.RolePermissions
                .IgnoreQueryFilters(["tenant"]).CountAsync();
            await PlatformGranularCutoverStartupGuard.ValidateAsync(db,
                Config(true, false, name), isProduction: true);
            await PlatformGranularCutoverStartupGuard.ValidateAsync(db,
                Config(false, true, name), isProduction: true);
            Assert.Equal(grantsBefore, await db.RolePermissions
                .IgnoreQueryFilters(["tenant"]).CountAsync()); // read-only

            var revoked = await db.RolePermissions.IgnoreQueryFilters(["tenant"])
                .FirstAsync(x => x.TenantId == master && x.RoleId == role.Id);
            db.RolePermissions.Remove(revoked);
            await db.SaveChangesAsync();
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                PlatformGranularCutoverStartupGuard.ValidateAsync(db,
                    Config(true, false, name), isProduction: true));

            // Rollback of feature flags must still permit startup under the
            // coarse live SystemAdministrator boundary, without regranting.
            await PlatformGranularCutoverStartupGuard.ValidateAsync(db,
                Config(false, false), isProduction: true);
            Assert.Equal(grantsBefore - 1, await db.RolePermissions
                .IgnoreQueryFilters(["tenant"]).CountAsync());
        });
    }

    [Fact]
    public async Task Older_production_schema_must_not_enable_granular_endpoints()
    {
        await WithDatabaseAsync(async (db, name) =>
        {
            // Even if the operator mistakenly supplies an acknowledgement,
            // the earlier separately approved uniqueness migration is still
            // required for an integrity-preserving Production cutover.
            await db.Database.MigrateAsync("20261023210000_platformaccessdenialaudit");
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                PlatformGranularCutoverStartupGuard.ValidateAsync(db,
                    Config(true, true, name), isProduction: true));
        }, applyLatestMigration: false);
    }

    private static IConfiguration Config(
        bool roles, bool permissions, string? database = null, Guid? masterId = null)
    {
        var values = new Dictionary<string, string?>
        {
            ["Identity:PlatformPermissions:EnforceRoleEndpoints"] = roles.ToString(),
            ["Identity:PlatformPermissions:EnforcePermissionEndpoints"] = permissions.ToString(),
            ["Identity:PlatformPermissions:AllowProductionGranularCutover"] =
                (database is not null).ToString(),
            ["Identity:PlatformPermissions:ReviewedDatabaseName"] = database,
            ["Identity:PlatformPermissions:ReviewedMasterTenantId"] =
                (masterId ?? DefaultSeedData.MasterTenant.Id).ToString()
        };
        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }

    private static async Task WithDatabaseAsync(
        Func<IdentityDbContext, string, Task> run, bool applyLatestMigration = true)
    {
        var raw = Environment.GetEnvironmentVariable("SHINERA_SQLSERVER_TEST_CONNECTION");
        if (string.IsNullOrWhiteSpace(raw))
            throw new InvalidOperationException("Disposable SQL Server required.");
        var connection = new SqlConnectionStringBuilder(raw)
        {
            InitialCatalog = "ShineraCutoverGate_" + Guid.NewGuid().ToString("N"),
            ConnectTimeout = 30
        };
        var options = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlServer(connection.ConnectionString).Options;
        await using var db = new IdentityDbContext(options, new TenantContext());
        try
        {
            if (applyLatestMigration)
                await db.Database.MigrateAsync();
            else
                await db.Database.MigrateAsync(
                    "20261023210000_platformaccessdenialaudit");
            await run(db, connection.InitialCatalog);
        }
        finally
        {
            await db.Database.EnsureDeletedAsync();
        }
    }
}
