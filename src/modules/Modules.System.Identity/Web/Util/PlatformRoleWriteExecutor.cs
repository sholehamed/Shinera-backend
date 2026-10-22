using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Modules.System.Identity.Infrastructure.Persistence.Interceptors;
using OpenIddict.Abstractions;

namespace Modules.System.Identity.Web.Util;

/// <summary>
/// Executes legacy Role commands under one verified and bounded master-write
/// gateway. The gateway alone owns live DB checks and EF read/write scope setup.
/// </summary>
public sealed class PlatformRoleWriteExecutor(
    AuthorizedPlatformMasterWrite gateway,
    ILogger<PlatformRoleWriteExecutor> logger)
{
    public async Task<T> ExecuteAsync<T>(
        ClaimsPrincipal principal,
        string operation,
        Func<Task<T>> execute,
        Guid? targetRoleId = null,
        CancellationToken cancellationToken = default)
    {
        using var authorized = await gateway.BeginAsync(principal, targetRoleId, cancellationToken);
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
        CancellationToken cancellationToken = default)
        => ExecuteAsync(principal, operation, async () =>
        {
            await execute();
            return true;
        }, targetRoleId, cancellationToken);
}
