using System.Data;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using Modules.System.Identity.Application.Abstractions;
using Modules.System.Identity.Infrastructure.Persistence;
using Modules.System.Identity.Infrastructure.Persistence.Interceptors;
using Modules.System.Identity.Infrastructure.Persistence.Contexts;
using OpenIddict.Abstractions;

namespace Modules.System.Identity.Web.Util;

/// <summary>
/// Executes legacy Role commands under one verified and bounded master-write
/// gateway. The gateway alone owns live DB checks and EF read/write scope setup.
/// </summary>
public sealed class PlatformRoleWriteExecutor(
    AuthorizedPlatformMasterWrite gateway,
    IdentityDbContext database,
    TrustedTenantWriteScope trustedWrites,
    ILogger<PlatformRoleWriteExecutor> logger)
{
    public async Task<T> ExecuteAsync<T>(
        ClaimsPrincipal principal,
        string operation,
        Func<Task<T>> execute,
        Guid? targetRoleId = null,
        CancellationToken cancellationToken = default,
        string? newRoleName = null)
    {
        if (operation == "roles.permissions.replace")
        {
            if (targetRoleId is null || targetRoleId == Guid.Empty)
                throw new UnauthorizedAccessException("A validated Role target is required.");
            var strategy = database.Database.CreateExecutionStrategy();
            return await strategy.ExecuteAsync(async () =>
            {
                await using var transaction = await database.Database.BeginTransactionAsync(
                    IsolationLevel.Serializable, cancellationToken);
                var result = await ExecuteAuthorizedAsync(principal, operation, execute,
                    targetRoleId, cancellationToken, newRoleName);
                await transaction.CommitAsync(cancellationToken);
                return result;
            });
        }

        return await ExecuteAuthorizedAsync(principal, operation, execute,
            targetRoleId, cancellationToken, newRoleName);
    }

    private async Task<T> ExecuteAuthorizedAsync<T>(
        ClaimsPrincipal principal, string operation, Func<Task<T>> execute,
        Guid? targetRoleId, CancellationToken cancellationToken, string? newRoleName)
    {
        using var authorized = await gateway.BeginAsync(principal, targetRoleId, cancellationToken);

        // The live SystemAdministrator grant is determined by the persisted
        // SUPERADMIN role name. Ordinary Role CRUD must not forge, rename or
        // dismantle this privileged identity. Use a reviewed migration instead.
        if (string.Equals(newRoleName?.Trim(), "superadmin", StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("The platform SuperAdmin role is reserved.");

        if (targetRoleId.HasValue)
        {
            var normalizedName = await database.Roles.AsNoTracking()
                .Where(role => role.Id == targetRoleId.Value &&
                               role.TenantId == DefaultSeedData.MasterTenant.Id)
                .Select(role => role.NormalizedName)
                .SingleOrDefaultAsync(cancellationToken);

            if (string.Equals(normalizedName?.Trim(), "SUPERADMIN", StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("The platform SuperAdmin role cannot be modified through ordinary CRUD.");
        }

        // Authorize RolePermission changes only for this exact reviewed role.
        // All other role writes retain no grant mutation authority.
        using var grant = operation == "roles.permissions.replace"
            ? trustedWrites.BeginPlatformGrantMutation(
                PlatformGrantMutationKind.RolePermissions,
                targetRoleId ?? throw new UnauthorizedAccessException("Role target is required."))
            : null;

        var actor = principal.FindFirst(OpenIddictConstants.Claims.Subject)?.Value;
        logger.LogInformation("Platform role operation {Operation} started by {ActorId} for {RoleId}",
            operation, actor, targetRoleId);
        try
        {
            var auditRoleId = operation == "roles.permissions.replace" ? targetRoleId : null;
            var before = auditRoleId.HasValue
                ? (await database.RolePermissions.AsNoTracking()
                    .Where(x => x.TenantId == DefaultSeedData.MasterTenant.Id &&
                                x.RoleId == auditRoleId.Value)
                    .Select(x => x.PermissionId)
                    .ToListAsync(cancellationToken)).ToHashSet()
                : null;

            var result = await execute();

            if (before is not null && auditRoleId.HasValue)
            {
                if (!Guid.TryParse(actor, out var actorId))
                    throw new UnauthorizedAccessException("Invalid platform actor for audit.");

                var after = (await database.RolePermissions.AsNoTracking()
                    .Where(x => x.TenantId == DefaultSeedData.MasterTenant.Id &&
                                x.RoleId == auditRoleId.Value)
                    .Select(x => x.PermissionId)
                    .ToListAsync(cancellationToken)).ToHashSet();

                foreach (var permissionId in after.Except(before).OrderBy(x => x))
                    await PlatformGrantAuditWriter.RecordAsync(database, actorId,
                        "RolePermission", auditRoleId.Value, permissionId, "grant",
                        previousGrant: false, currentGrant: true,
                        cancellationToken: cancellationToken);

                foreach (var permissionId in before.Except(after).OrderBy(x => x))
                    await PlatformGrantAuditWriter.RecordAsync(database, actorId,
                        "RolePermission", auditRoleId.Value, permissionId, "revoke",
                        previousGrant: true, currentGrant: false,
                        cancellationToken: cancellationToken);
            }

            logger.LogInformation("Platform role operation {Operation} completed by {ActorId}",
                operation, actor);
            return result;
        }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Platform role operation {Operation} failed for actor {ActorId}",
                operation, actor);
            throw;
        }
    }

    public Task ExecuteAsync(
        ClaimsPrincipal principal,
        string operation,
        Func<Task> execute,
        Guid? targetRoleId = null,
        CancellationToken cancellationToken = default,
        string? newRoleName = null)
        => ExecuteAsync(principal, operation, async () =>
        {
            await execute();
            return true;
        }, targetRoleId, cancellationToken, newRoleName);
}
