using System.Security.Claims;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Modules.System.Identity.Infrastructure.Persistence;
using Modules.System.Identity.Infrastructure.Persistence.Contexts;
using OpenIddict.Abstractions;

namespace Modules.System.Identity.Web.Util;

/// <summary>
/// Captures only a failed SystemAdministrator policy decision for mapped API
/// endpoints. Never stores request URLs, route parameters, query strings,
/// Authorization headers, JWTs, client IPs, payloads or exception messages.
/// An authenticated, validated System principal is the only trusted actor ID.
/// </summary>
public sealed class PlatformAccessDenialAudit(IdentityDbContext database)
{
    public async Task RecordAsync(HttpContext context, bool challenged,
        CancellationToken cancellationToken)
    {
        if (context.GetEndpoint() is not RouteEndpoint route)
            throw new InvalidOperationException(
                "Platform denial audit requires a registered route endpoint.");

        var template = route.RoutePattern.RawText ?? "";
        var method = context.Request.Method.ToUpperInvariant();

        // Bounded server-controlled template, NOT the client's Path or QueryString.
        if (template.Length == 0 || template.Length > 256 ||
            method is not ("GET" or "POST" or "PUT" or "PATCH" or "DELETE" or "HEAD" or "OPTIONS"))
            throw new InvalidOperationException("Unsupported platform audit metadata.");

        Guid? actorId = null;
        if (context.User.Identity?.IsAuthenticated == true &&
            context.User.HasClaim("account_type", "system") &&
            !context.User.HasClaim(c => c.Type == "tenant_id") &&
            Guid.TryParse(context.User.FindFirstValue(OpenIddictConstants.Claims.Subject), out var parsed))
        {
            actorId = parsed;
        }

        var id = Guid.NewGuid();
        var master = DefaultSeedData.MasterTenant.Id;
        var outcome = challenged ? "challenge" : "forbidden";

        // This is a new SQL command and autocommit, outside the rejected action's
        // transaction. No EF DbSet/SaveChanges hook can mutate audit history.
        await database.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO [dbo].[PlatformAccessDenialAuditEntries]
                ([Id], [TenantId], [ActorUserId], [HttpMethod], [RouteTemplate], [Outcome])
            VALUES
                ({id}, {master}, {actorId}, {method}, {template}, {outcome})
            """, cancellationToken);
    }
}

/// <summary>
/// Decorates the default ASP.NET Core authorization result handler. On
/// privilege failure the audit write happens before 401/403 is emitted. An
/// audit outage returns 503 without invoking the protected endpoint: it does
/// NOT change an authorization failure to success. Other authorization policies
/// and successful requests behave exactly as before.
/// </summary>
public sealed class AuditedPlatformAuthorizationResultHandler(
    PlatformAccessDenialAudit audit,
    ILogger<AuditedPlatformAuthorizationResultHandler> logger)
    : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler _defaultHandler = new();

    public async Task HandleAsync(RequestDelegate next, HttpContext context,
        AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
    {
        if (authorizeResult.Succeeded ||
            (!authorizeResult.Challenged && !authorizeResult.Forbidden) ||
            !policy.Requirements.OfType<ActiveSystemAdministratorRequirement>().Any())
        {
            await _defaultHandler.HandleAsync(next, context, policy, authorizeResult);
            return;
        }

        try
        {
            await audit.RecordAsync(context, authorizeResult.Challenged,
                context.RequestAborted);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // Never include bearer tokens, URL, request body or SQL detail in
            // logging. The response is fail-closed and generic.
            logger.LogError("Could not persist platform denial audit for a failed authorization.");
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return;
        }

        await _defaultHandler.HandleAsync(next, context, policy, authorizeResult);
    }
}
