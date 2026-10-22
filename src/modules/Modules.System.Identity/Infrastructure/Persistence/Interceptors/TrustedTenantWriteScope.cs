using Microsoft.Extensions.Logging;
using Modules.System.Identity.Application.Abstractions;

namespace Modules.System.Identity.Infrastructure.Persistence.Interceptors;

/// <summary>
/// Infrastructure-owned write overrides. Query-filter bypass is intentionally NOT
/// a write bypass. Only trusted infrastructure code can open these scopes.
/// </summary>
public sealed class TrustedTenantWriteScope(ILogger<TrustedTenantWriteScope> logger)
{
    private int _bootstrapDepth;
    private Guid? _platformTenant;
    private Guid? _platformActor;

    internal bool IsBootstrap => _bootstrapDepth > 0;
    internal bool AllowsPlatformTenant(Guid tenantId) =>
        _platformTenant == tenantId && _platformActor.HasValue;

    /// <summary>For startup migrations/seeding, never for a request handler.</summary>
    internal IDisposable BeginBootstrapWrites()
    {
        _bootstrapDepth++;
        logger.LogWarning("Trusted bootstrap write scope entered");
        return new GuardedScope(() =>
        {
            _bootstrapDepth--;
            logger.LogWarning("Trusted bootstrap write scope exited");
        });
    }

    /// <summary>
    /// Reserved for an explicitly authorized/audited platform operation.
    /// This is NOT opened automatically merely because a JWT says superadmin.
    /// </summary>
    internal IDisposable BeginPlatformMasterWrite(ITenantContext subject, Guid actorUserId, Guid storageTenantId)
    {
        if (!subject.IsSystemContext || !subject.IsSuperAdmin ||
            subject.UserId != actorUserId || actorUserId == Guid.Empty ||
            storageTenantId != DefaultSeedData.MasterTenant.Id ||
            _platformActor.HasValue)
        {
            throw new UnauthorizedAccessException("Platform write scope requires a verified system administrator and the master storage scope.");
        }

        _platformTenant = storageTenantId;
        _platformActor = actorUserId;
        logger.LogWarning("Trusted platform write scope entered for actor {ActorId}", actorUserId);
        return new GuardedScope(() =>
        {
            logger.LogWarning("Trusted platform write scope exited for actor {ActorId}", actorUserId);
            _platformActor = null;
            _platformTenant = null;
        });
    }

    private sealed class GuardedScope(Action dispose) : IDisposable
    {
        private bool _closed;
        public void Dispose()
        {
            if (_closed) return;
            _closed = true;
            dispose();
        }
    }
}
