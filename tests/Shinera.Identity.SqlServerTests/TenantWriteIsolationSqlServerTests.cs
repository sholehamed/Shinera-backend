using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
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
