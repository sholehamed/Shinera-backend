using Domain.SharedKernel.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Modules.System.Identity.Application.Abstractions;

namespace Modules.System.Identity.Infrastructure.Persistence.Interceptors;

/// <summary>
/// Fail-closed write guard for every IMustHaveTenant record.
/// Read-scope overrides NEVER authorize writes.
/// </summary>
public sealed class TenantSaveChangesInterceptor(
    ITenantContext tenant, TrustedTenantWriteScope trustedWrites) : SaveChangesInterceptor
{
    public override InterceptionResult<int> SavingChanges(
        DbContextEventData eventData, InterceptionResult<int> result)
    {
        GuardWrites(eventData.Context);
        return base.SavingChanges(eventData, result);
    }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData, InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        GuardWrites(eventData.Context);
        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    private void GuardWrites(DbContext? context)
    {
        if (context is null) return;

        foreach (var entry in context.ChangeTracker.Entries<IMustHaveTenant>())
        {
            if (entry.State is EntityState.Unchanged or EntityState.Detached) continue;

            if (entry.State is EntityState.Modified or EntityState.Deleted)
            {
                var original = (Guid)entry.Property(nameof(IMustHaveTenant.TenantId)).OriginalValue!;
                if (original != entry.Entity.TenantId)
                    throw new UnauthorizedAccessException("Tenant reassignment is forbidden.");
            }

            if (trustedWrites.IsBootstrap) continue;

            if (entry.State == EntityState.Added && entry.Entity.TenantId == Guid.Empty)
                entry.Entity.TenantId = tenant.ActiveTenantId
                    ?? throw new UnauthorizedAccessException("An active writable tenant is required.");

            var targetTenant = entry.Entity.TenantId;

            if (trustedWrites.AllowsPlatformTenant(targetTenant))
                continue;

            // A System account cannot pick a TenantId in a request payload and
            // thereby gain permission to write to that tenant.
            if (tenant.IsSystemContext || tenant.UserId is null ||
                targetTenant == Guid.Empty ||
                !tenant.WritableTenantIds.Contains(targetTenant))
            {
                throw new UnauthorizedAccessException("Write denied outside the authorized tenant scope.");
            }
        }
    }
}
