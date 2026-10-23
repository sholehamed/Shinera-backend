-- SHINERA / P0 #11 / READ ONLY Production Master-grants inventory
-- Requires sqlcmd variable -v MasterTenantId="<fixed DefaultSeedData.MasterTenant.Id>"
-- Review both target database and configured fixed Master GUID out of band.
-- Only SELECT statements: no seeds, elevated write scopes, GRANTs or toggles.
-- Never publish output containing real user IDs outside approved storage.
SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;

DECLARE @Master uniqueidentifier = TRY_CONVERT(uniqueidentifier, '$(MasterTenantId)');
IF @Master IS NULL OR @Master = '00000000-0000-0000-0000-000000000000'
    THROW 51040, 'Supply the reviewed fixed Master Tenant GUID.', 1;

SELECT DB_NAME() AS DatabaseName, @Master AS ExpectedMasterTenantId,
       COUNT_BIG(*) AS ActiveMasterRows
FROM dbo.Tenants WHERE Id = @Master AND IsActive = 1;

-- The expected catalog intentionally matches PlatformPermissionCatalog.Definitions.
-- Reconcile with the deployed commit BEFORE approving any migration/backfill.
DECLARE @Catalog TABLE (Code nvarchar(100) NOT NULL PRIMARY KEY);
INSERT INTO @Catalog(Code) VALUES
('ROLES.CREATE'), ('ROLES.UPDATE'), ('ROLES.DELETE'),
('ROLES.CHANGE-STATE'), ('ROLES.ASSIGN-PERMISSIONS'),
('PERMISSIONS.CREATE'), ('PERMISSIONS.UPDATE'),
('PERMISSIONS.DELETE'), ('PERMISSIONS.CHANGE-STATE');

SELECT c.Code AS ExpectedCode,
       COUNT_BIG(p.Id) AS MatchingRows,
       SUM(CASE WHEN p.IsActive = 1 THEN 1 ELSE 0 END) AS ActiveRows
FROM @Catalog c
LEFT JOIN dbo.Permissions p ON UPPER(LTRIM(RTRIM(p.Code))) = c.Code
GROUP BY c.Code ORDER BY c.Code;

SELECT r.Id AS RoleId, r.NormalizedName, r.IsActive, r.TenantId
FROM dbo.Roles r
WHERE r.TenantId = @Master AND r.NormalizedName = 'SUPERADMIN';

-- REVIEW human identities out of band. System users must have User.TenantId NULL;
-- Master appears on UserRole/RolePermission only as storage scope.
SELECT ur.Id AS AssignmentId, ur.UserId, ur.RoleId,
       u.UserTpe AS UserKind, u.TenantId AS UserTenantId,
       u.IsActive AS UserActive, r.TenantId AS RoleStorageTenantId
FROM dbo.UserRoles ur
LEFT JOIN dbo.Users u ON u.Id = ur.UserId
LEFT JOIN dbo.Roles r ON r.Id = ur.RoleId
WHERE ur.TenantId = @Master;

SELECT r.Id AS RoleId, c.Code AS ExpectedCode,
       p.Id AS PermissionId, rp.Id AS ExistingGrantId
FROM dbo.Roles r
CROSS JOIN @Catalog c
LEFT JOIN dbo.Permissions p
       ON UPPER(LTRIM(RTRIM(p.Code))) = c.Code AND p.IsActive = 1
LEFT JOIN dbo.RolePermissions rp
       ON rp.TenantId = @Master AND rp.RoleId = r.Id
      AND rp.PermissionId = p.Id
WHERE r.TenantId = @Master AND r.NormalizedName = 'SUPERADMIN'
ORDER BY c.Code;

-- A direct System user denial overrides role grants.
SELECT up.Id AS DenialId, up.UserId, p.Code
FROM dbo.UserPermissions up
JOIN dbo.Users u ON u.Id = up.UserId
JOIN dbo.Permissions p ON p.Id = up.PermissionId
WHERE up.TenantId = @Master AND up.IsGranted = 0
  AND u.UserTpe = 1 AND u.TenantId IS NULL
  AND (p.Code LIKE 'ROLES.%' OR p.Code LIKE 'PERMISSIONS.%');

-- A manually approved backfill must also inspect GroupRoles/UserGroups and
-- stale users/roles. Do not infer authorization from JWT claims or this report.
