-- READ-ONLY Production preflight for upcoming Permission.Code uniqueness DDL.
-- Run in the selected database with reviewed permissions and export the result
-- securely. Do not auto-merge, delete Permission IDs, or rewrite grants.
-- SQL Server 2022; same expression/collation as the migration.
SET NOCOUNT ON;

SELECT [Id], [Code], [IsActive], [ResourceId]
FROM [dbo].[Permissions]
WHERE [Code] IS NULL OR LEN(LTRIM(RTRIM([Code]))) NOT BETWEEN 1 AND 100
ORDER BY [Code], [Id];

SELECT UPPER(LTRIM(RTRIM([Code]))) COLLATE Latin1_General_100_CI_AS AS [NormalizedCode],
       COUNT_BIG(*) AS [Total]
FROM [dbo].[Permissions]
GROUP BY UPPER(LTRIM(RTRIM([Code]))) COLLATE Latin1_General_100_CI_AS
HAVING COUNT_BIG(*) > 1
ORDER BY [NormalizedCode];

-- Investigate IDs and ALL references (RolePermissions/UserPermissions and
-- related grants) for each duplicate group before any manual remediation.
-- A clean preflight is required but not enough: prevent concurrent writes
-- between preflight and the transactional indexed schema migration.
