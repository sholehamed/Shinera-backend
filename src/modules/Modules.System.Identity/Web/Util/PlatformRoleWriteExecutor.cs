using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Modules.System.Identity.Application.Abstractions;
using Modules.System.Identity.Domain.Entities;
using Modules.System.Identity.Infrastructure.Persistence;
using Modules.System.Identity.Infrastructure.Persistence.Interceptors;
using OpenIddict.Abstractions;

namespace Modules.System.Identity.Web.Util;

/// <summary>
/// Bounds legacy Role command execution to the master permission storage scope.
/// Enforces LIVE administrator membership independently of JWT role claims.
/// This never grants ordinary System requests arbitrary tenant write privileges.
/// </summary>
public sealed class PlatformRoleWriteExecutor(
    IIdentityDbContext database,
    ITenantContext tenant,
    TrustedTenantWriteScope trustedWrites,
    ILogger<PlatformRoleWriteExecutor> logger)
{
    public async Task<T> ExecuteAsync<T>(
        ClaimsPrincipal principal,
        string operation,
        Func<Task<T>> execute,
        Guid? targetRoleId = null,
        CancellationToken cancellationToken = default)
    {
        var userId = await CheckAuthorizationAsync(principal, targetRoleId, cancellationToken);
        // Suppress the read filter ONLY around a verified Master Tenant operation.
        using var readable = tenant.DisableFilter();
        using var writable = trustedWrites.BeginPlatformMasterWrite(
            tenant, userId, DefaultSeedData.MasterTenant.Id);
        logger.LogInformation("Platform role operation {Operation} started by {ActorId} for {RoleId}",
            operation, userId, targetRoleId);
        try
        {
            var result = await execute();
            logger.LogInformation("Platform role operation {Operation} completed by {ActorId}",
                operation, userId);
            return result;
        }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Platform role operation {Operation} failed for actor {ActorId}",
                operation, userId);
            throw;
        }
    }

    public Task ExecuteAsync(
        ClaimsPrincipal principal,
        string operation,
        Func<Task> execute,
        Guid? targetRoleId = null,
        CancellationToken cancellationToken = default)
        => ExecuteAsync(principal, operation, async () =>
        {
            await execute();
            return true;
        }, targetRoleId, cancellationToken);

    private async Task<Guid> CheckAuthorizationAsync(
        ClaimsPrincipal principal, Guid? targetRoleId, CancellationToken ct)
    {
        if (!SystemAuthorizationPolicies.IsSystemAdministrator(principal) ||
            !Guid.TryParse(principal.FindFirstValue(OpenIddictConstants.Claims.Subject), out var userId) ||
            !tenant.IsSystemContext || !tenant.IsSuperAdmin || tenant.UserId != userId)
            throw new UnauthorizedAccessException("Platform operation denied.");

        var masterId = DefaultSeedData.MasterTenant.Id;
        var activeUser = await database.Users.AsNoTracking().AnyAsync(x =>
            x.Id == userId && x.TenantId == null && x.UserTpe == UserType.System &&
            x.IsActive && (!x.IsLockedOut || x.LockoutEndUtc <= DateTime.UtcNow), ct);
        var liveAdminRole = await database.UserRoles.IgnoreQueryFilters(["tenant"])
            .AsNoTracking().AnyAsync(x => x.UserId == userId && x.TenantId == masterId &&
                x.Role.TenantId == masterId && x.Role.IsActive &&
                x.Role.NormalizedName == "SUPERADMIN", ct);
        var masterActive = await database.Tenants.AsNoTracking()
            .AnyAsync(x => x.Id == masterId && x.IsActive, ct);

        if (!activeUser || !liveAdminRole || !masterActive)
            throw new UnauthorizedAccessException("Platform administrator role revoked or disabled.");

        if (targetRoleId.HasValue && !await database.Roles.IgnoreQueryFilters(["tenant"])
            .AsNoTracking().AnyAsync(x =>
                x.Id == targetRoleId.Value && x.TenantId == masterId, ct))
            throw new UnauthorizedAccessException("Role is outside the platform storage scope.");

        return userId;
    }
}
