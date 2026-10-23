using System.Data;
using Microsoft.Data.SqlClient;
using Modules.System.Identity.Infrastructure.Persistence;

// Deliberately separate from the Web API: no development mutation endpoint,
// authentication bypass, or production-registered service is introduced.
// This tool is run only from the disposable GitHub SQL Server HTTP E2E step.
const string optIn = "stale-jwt-ci-only";
var databaseName = Environment.GetEnvironmentVariable("DBNAME") ?? "";
var server = Environment.GetEnvironmentVariable("DataBaseServer") ?? "";
if (args.Length != 2 ||
    args[0] != "revoke-seeded-superadmin" ||
    !Guid.TryParse(args[1], out var subject) ||
    subject == Guid.Empty ||
    Environment.GetEnvironmentVariable("SHINERA_E2E_DB_MUTATION") != optIn ||
    Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") != "Development" ||
    Environment.GetEnvironmentVariable("Identity__E2E__Enabled") != "true" ||
    !databaseName.StartsWith("Shinera_E2E_", StringComparison.Ordinal) ||
    server is not ("127.0.0.1,1433" or "localhost,1433"))
{
    throw new InvalidOperationException(
        "The CI-only database mutator requires an explicit disposable Development database and valid subject.");
}

var user = Environment.GetEnvironmentVariable("DataBaseUsername");
var password = Environment.GetEnvironmentVariable("DataBasePassword");
if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(password))
    throw new InvalidOperationException("Missing disposable SQL Server credentials.");

var connectionString = new SqlConnectionStringBuilder
{
    DataSource = server,
    InitialCatalog = databaseName,
    UserID = user,
    Password = password,
    Encrypt = SqlConnectionEncryptOption.Optional,
    TrustServerCertificate = true
}.ConnectionString;

await using var connection = new SqlConnection(connectionString);
await connection.OpenAsync();
await using var transaction = (SqlTransaction)await connection.BeginTransactionAsync(
    IsolationLevel.Serializable);

// Only the existing seeded, null-tenant System "admin" may be targeted.
// Do not touch Tenant users or other identities even in CI.
await using (var verify = new SqlCommand("""
    SELECT COUNT_BIG(*)
    FROM [dbo].[Users] WITH (UPDLOCK, HOLDLOCK)
    WHERE [Id] = @subject AND [TenantId] IS NULL AND [UserTpe] = 1
      AND [NormalizedUserName] = N'ADMIN' AND [IsActive] = 1;
    """, connection, transaction))
{
    verify.Parameters.Add("@subject", SqlDbType.UniqueIdentifier).Value = subject;
    var matching = Convert.ToInt64(await verify.ExecuteScalarAsync());
    if (matching != 1)
        throw new InvalidOperationException("Refusing to mutate a non-seeded or non-System identity.");
}

// Intentionally model persisted SQL-level revocation independently of the
// public grant APIs, which must not permit SuperAdmin self-revocation.
// Direct SQL is allowed ONLY in this disposable E2E DB. It does NOT constitute
// a tested or approved production grant-mutation/audit path.
await using (var revoke = new SqlCommand("""
    DELETE ur
    FROM [dbo].[UserRoles] AS ur
    INNER JOIN [dbo].[Roles] AS role ON role.[Id] = ur.[RoleId]
    WHERE ur.[UserId] = @subject AND ur.[TenantId] = @master
      AND role.[TenantId] = @master
      AND role.[NormalizedName] = N'SUPERADMIN';
    """, connection, transaction))
{
    revoke.Parameters.Add("@subject", SqlDbType.UniqueIdentifier).Value = subject;
    revoke.Parameters.Add("@master", SqlDbType.UniqueIdentifier).Value =
        DefaultSeedData.MasterTenant.Id;
    var affected = await revoke.ExecuteNonQueryAsync();
    if (affected != 1)
        throw new InvalidOperationException(
            $"Expected exactly one seeded SuperAdmin assignment, found {affected}; transaction rolled back.");
}

await transaction.CommitAsync();
Console.WriteLine("PASS: disposable SQL Server removed exactly one seeded SuperAdmin assignment.");
