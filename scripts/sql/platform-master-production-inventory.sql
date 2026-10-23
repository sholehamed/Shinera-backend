-- SHINERA / P0 #11 / READ ONLY Production Master-grants inventory
-- Requires sqlcmd variable -v MasterTenantId="<fixed DefaultSeedData.MasterTenant.Id>"
-- Review both target database and configured fixed Master GUID out of band.
-- Only reads of persistent tables; the local @Catalog table variable is populated\n-- from literals. No persistent table mutations, elevated writes or flag toggles.
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

-- Diagnose incompatible fixed-Master grant edges; each is a blocking anomaly
-- even if the referenced row exists and all foreign keys are valid.
SELECT 'RolePermission' AS RelationshipKind, COUNT_BIG(*) AS InvalidMasterLinks
FROM dbo.RolePermissions rp
JOIN dbo.Roles r ON r.Id = rp.RoleId
WHERE rp.TenantId = @Master AND r.TenantId != @Master
UNION ALL
SELECT 'GroupRole', COUNT_BIG(*)
FROM dbo.GroupRoles gr
JOIN dbo.Roles r ON r.Id = gr.RoleId
JOIN dbo.Groups g ON g.Id = gr.GroupId
WHERE gr.TenantId = @Master AND
      (r.TenantId != @Master OR g.TenantId != @Master)
UNION ALL
SELECT 'UserGroup', COUNT_BIG(*)
FROM dbo.UserGroups ug
JOIN dbo.Groups g ON g.Id = ug.GroupId
JOIN dbo.Users u ON u.Id = ug.UserId
WHERE ug.TenantId = @Master AND
      (g.TenantId != @Master OR u.UserTpe != 1 OR u.TenantId IS NOT NULL)
UNION ALL
SELECT 'UserPermission', COUNT_BIG(*)
FROM dbo.UserPermissions up
JOIN dbo.Users u ON u.Id = up.UserId
WHERE up.TenantId = @Master AND
      (u.UserTpe != 1 OR u.TenantId IS NOT NULL);

-- An approved rollout must additionally review *all* role and group paths,
-- change drift during inventory, actual user principal status, and backups.
-- The report is never authorization to enable granular enforcement.
