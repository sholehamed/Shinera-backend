using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Modules.System.Identity.Infrastructure.Persistence.Contexts;

namespace Modules.System.Identity.Infrastructure.Persistence;

/// <summary>
/// Fail-closed STARTUP safeguard for enabling granular platform Role/Permission
/// authorization in Production. Read-only checks: NEVER applies grants,
/// mutates feature flags or performs a cutover. It is not an approval service,
/// digital signature verification or a replacement for a production rollout.
/// Granular endpoint policies are mapped once per process; rollback requires
/// restoring flags OFF and restarting ALL application instances.
/// </summary>
public static class PlatformGranularCutoverStartupGuard
{
    private const string Prefix = "Identity:PlatformPermissions:";
    private const string UniquenessMigration = "20261024200000_permissioncodeuniqueness";

    public static async Task ValidateAsync(
        IdentityDbContext db, IConfiguration configuration, bool isProduction,
        CancellationToken ct = default)
    {
        // Development CI explicitly enables granular checks with its disposable
        // fixtures; it must not be subject to Production deployment approval.
        if (!isProduction)
            return;

        var rolesEnabled = configuration.GetValue<bool>(Prefix + "EnforceRoleEndpoints");
        var permissionsEnabled = configuration.GetValue<bool>(Prefix + "EnforcePermissionEndpoints");

        // Safe rollback state. Coarse live SystemAdministrator checks remain
        // active regardless of both granular flags.
        if (!rolesEnabled && !permissionsEnabled)
            return;

        // Explicit default-OFF deployment interlock, entirely independent of
        // the endpoint-specific flags. The reviewed DB + Master bindings guard
        // against accidental application to a different target instance.
        // These values are operational acknowledgements, NOT cryptographic
        // evidence of two-person signoff. No API/CLI sets them automatically.
        if (!configuration.GetValue<bool>(Prefix + "AllowProductionGranularCutover") ||
            !Guid.TryParse(configuration[Prefix + "ReviewedMasterTenantId"],
                out var reviewedMaster) ||
            reviewedMaster != DefaultSeedData.MasterTenant.Id ||
            string.IsNullOrWhiteSpace(configuration[Prefix + "ReviewedDatabaseName"]) ||
            !string.Equals(
                configuration[Prefix + "ReviewedDatabaseName"],
                db.Database.GetDbConnection().Database,
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                "Production granular authorization requires an independently reviewed deployment and exact database/Master acknowledgement.");

        // An absent normalized Permission.Code UNIQUE index allows concurrent
        // catalog drift, so enabling granular policies remains unsafe.
        var applied = await db.Database.GetAppliedMigrationsAsync(ct);
        if (!applied.Contains(UniquenessMigration, StringComparer.Ordinal))
            throw new InvalidOperationException(
                "Production Permission.Code uniqueness migration must be separately approved and applied before granular cutover.");

        // Require the complete narrow 5A scope audit. This does NOT guarantee
        // correctness of all identities or the real operator-approved proposal.
        var inventory = await PlatformProductionGrantInventory.ReadAsync(db, ct);
        if (inventory.HasBlockingFindings)
            throw new InvalidOperationException(
                "Production Master authorization inventory has blocking findings. Keep granular flags OFF.");
    }
}
