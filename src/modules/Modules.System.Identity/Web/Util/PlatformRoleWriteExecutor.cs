using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using Modules.System.Identity.Application.Abstractions;
using Modules.System.Identity.Infrastructure.Persistence;
using Modules.System.Identity.Infrastructure.Persistence.Interceptors;
using OpenIddict.Abstractions;

namespace Modules.System.Identity.Web.Util;

/// <summary>
/// Executes legacy Role commands under one verified and bounded master-write
/// gateway. The gateway alone owns live DB checks and EF read/write scope setup.
/// </summary>
public sealed class PlatformRoleWriteExecutor(
    AuthorizedPlatformMasterWrite gateway,
    IIdentityDbContext database,
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
            var result = await execute();
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
