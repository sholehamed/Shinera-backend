using System.Data;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Modules.System.Identity.Application.Abstractions;
using Modules.System.Identity.Domain.Entities;
using Modules.System.Identity.Infrastructure.Persistence;
using Modules.System.Identity.Infrastructure.Persistence.Interceptors;
using Modules.System.Identity.Infrastructure.Persistence.Contexts;
using OpenIddict.Abstractions;

namespace Modules.System.Identity.Web.Util;

/// <summary>
/// Limits System group member grants to active master-scoped groups and active
/// System users. SuperAdmin membership is reserved for reviewed bootstrap.
/// </summary>
public sealed class PlatformGroupMembershipWriteExecutor(
    AuthorizedPlatformMasterWrite gateway,
    IdentityDbContext database,
    TrustedTenantWriteScope trustedWrites,
    ILogger<PlatformGroupMembershipWriteExecutor> logger)
{
    public async Task ExecuteAsync(
        ClaimsPrincipal principal,
        Guid groupId,
        IReadOnlyCollection<Guid>? userIds,
        Func<Task> execute,
        CancellationToken cancellationToken = default)
    {
        // Authorization, handler changes, and audit commit atomically.
        var strategy = database.Database.CreateExecutionStrategy();
        await strategy.ExecuteAsync(async () =>
        {
            await using var transaction = await database.Database.BeginTransactionAsync(
                IsolationLevel.Serializable, cancellationToken);
            using var scope = await gateway.BeginAsync(principal, cancellationToken: cancellationToken);
            await ExecuteInsideTransactionAsync(principal, groupId, userIds, execute, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        });
    }

    private async Task ExecuteInsideTransactionAsync(
        ClaimsPrincipal principal, Guid groupId, IReadOnlyCollection<Guid>? userIds,
        Func<Task> execute, CancellationToken cancellationToken)
    {
        var master = DefaultSeedData.MasterTenant.Id;
        var members = userIds?.Distinct().ToArray() ?? [];

        if (groupId == Guid.Empty || members.Length == 0 ||
            members.Any(id => id == Guid.Empty))
            throw new UnauthorizedAccessException("A valid group and member list is required.");

        // Prevent a two-step self-grant: an administrator must not be able
        // to assign a role to a group and then join that group themselves.
        // This also rejects idempotent/self-including batches.
        if (!Guid.TryParse(principal.FindFirst(OpenIddictConstants.Claims.Subject)?.Value,
                out var actorId) || members.Contains(actorId))
            throw new UnauthorizedAccessException(
                "Platform administrators cannot add themselves to a group.");

        var groupIsValid = await database.Groups.AsNoTracking()
            .AnyAsync(g => g.Id == groupId && g.TenantId == master && g.IsActive, cancellationToken);
        if (!groupIsValid)
            throw new UnauthorizedAccessException("Group is outside the active platform master scope.");

        var isPrivilegedGroup = await database.GroupRoles.AsNoTracking()
            .AnyAsync(link => link.GroupId == groupId &&
                              link.TenantId == master &&
                              link.Role != null &&
                              link.Role.TenantId == master &&
                              link.Role.NormalizedName == "SUPERADMIN", cancellationToken);
        if (isPrivilegedGroup)
            throw new UnauthorizedAccessException("SuperAdmin group membership requires a reviewed bootstrap.");

        var validMembers = await database.Users.AsNoTracking()
            .CountAsync(user => members.Contains(user.Id) &&
                                user.UserTpe == UserType.System &&
                                user.TenantId == null && user.IsActive &&
                                (!user.IsLockedOut || user.LockoutEndUtc <= DateTime.UtcNow),
                cancellationToken);
        if (validMembers != members.Length)
            throw new UnauthorizedAccessException("Only active System accounts may join platform groups.");

        // This scope permits only UserGroup mutations for the validated group,
        // not UserRole/GroupRole/UserPermission or unrelated groups.
        using var grant = trustedWrites.BeginPlatformGrantMutation(
            PlatformGrantMutationKind.GroupMembers, groupId);

        var actor = principal.FindFirst(OpenIddictConstants.Claims.Subject)?.Value;
        logger.LogWarning("Platform group membership mutation {GroupId} by {ActorId} for {MemberCount} users",
            groupId, actor, members.Length);
        // Snapshot persisted links rather than requested IDs: no audit for
        // idempotent requests, and every actual change is accounted for.
        var before = (await database.UserGroups.AsNoTracking()
            .Where(x => x.TenantId == master && x.GroupId == groupId)
            .Select(x => x.UserId).ToListAsync(cancellationToken)).ToHashSet();

        await execute();

        var after = (await database.UserGroups.AsNoTracking()
            .Where(x => x.TenantId == master && x.GroupId == groupId)
            .Select(x => x.UserId).ToListAsync(cancellationToken)).ToHashSet();

        foreach (var userId in after.Except(before).OrderBy(x => x))
            await PlatformGrantAuditWriter.RecordAsync(database, actorId,
                "UserGroup", groupId, userId, "grant",
                previousGrant: false, currentGrant: true,
                cancellationToken: cancellationToken);
        foreach (var userId in before.Except(after).OrderBy(x => x))
            await PlatformGrantAuditWriter.RecordAsync(database, actorId,
                "UserGroup", groupId, userId, "revoke",
                previousGrant: true, currentGrant: false,
                cancellationToken: cancellationToken);

        logger.LogInformation("Platform group membership mutation completed for {GroupId} by {ActorId}",
            groupId, actor);
    }
}
