using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Modules.System.Identity.Application.Abstractions;
using Modules.System.Identity.Infrastructure.Persistence;
using Modules.System.Identity.Infrastructure.Persistence.Interceptors;
using OpenIddict.Abstractions;

namespace Modules.System.Identity.Web.Util;

/// <summary>
/// Live-validated, bounded System Permission mutations. Catalog/authorization
/// keys cannot be edited through CRUD even if granular enforcement is disabled.
/// Uses the same trusted master gateway as Role management.
/// </summary>
public sealed class PlatformPermissionWriteExecutor(
    AuthorizedPlatformMasterWrite gateway,
    IIdentityDbContext database,
    ILogger<PlatformPermissionWriteExecutor> logger)
{
    public async Task<T> ExecuteAsync<T>(
        ClaimsPrincipal principal,
        string operation,
        Func<Task<T>> execute,
        string? newCode = null,
        Guid? permissionId = null,
        CancellationToken cancellationToken = default)
    {
        using var authorized = await gateway.BeginAsync(principal,
            cancellationToken: cancellationToken);

        if (newCode is not null && PlatformPermissionCatalog.IsReservedCode(newCode))
            throw new UnauthorizedAccessException("Platform permission catalog keys are managed by versioned deployment.");

        if (permissionId.HasValue)
        {
            var currentCode = await database.Permissions.AsNoTracking()
                .Where(x => x.Id == permissionId.Value)
                .Select(x => x.Code).SingleOrDefaultAsync(cancellationToken);

            if (currentCode is not null && PlatformPermissionCatalog.IsReservedCode(currentCode))
                throw new UnauthorizedAccessException("Platform permission catalog keys cannot be modified through CRUD.");
        }

        var actor = principal.FindFirst(OpenIddictConstants.Claims.Subject)?.Value;
        logger.LogInformation("Platform permission operation {Operation} by {ActorId} for {PermissionId}",
            operation, actor, permissionId);
        try
        {
            var result = await execute();
            logger.LogInformation("Platform permission operation {Operation} completed by {ActorId}",
                operation, actor);
            return result;
        }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Platform permission operation {Operation} failed for {ActorId}",
                operation, actor);
            throw;
        }
    }

    public Task ExecuteAsync(
        ClaimsPrincipal principal, string operation, Func<Task> execute,
        string? newCode = null, Guid? permissionId = null,
        CancellationToken cancellationToken = default)
        => ExecuteAsync(principal, operation, async () =>
        {
            await execute();
            return true;
        }, newCode, permissionId, cancellationToken);
}
