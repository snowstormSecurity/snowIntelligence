-- VIEW:    currentStatus
-- PURPOSE: Shows the current import status of each fact table

CREATE VIEW [dbo].[currentStatus]
AS
SELECT 'adGroupMemberships' AS TableName, DateAdded, COUNT(DateAdded) AS Count
FROM dbo.adGroupMemberships
GROUP BY DateAdded
UNION
SELECT 'adUserAccounts' AS TableName, DateAdded, COUNT(DateAdded) AS Count
FROM dbo.adUserAccounts
GROUP BY DateAdded
UNION
SELECT 'assets' AS TableName, DateAdded, COUNT(DateAdded) AS Count
FROM dbo.assets
GROUP BY DateAdded
UNION
SELECT 'localGroupMembership' AS TableName, DateAdded, COUNT(DateAdded) AS Count
FROM dbo.localGroupmembership
GROUP BY DateAdded
UNION
SELECT 'people' AS TableName, DateAdded, COUNT(DateAdded) AS Count
FROM dbo.people
GROUP BY DateAdded
UNION
SELECT 'policy' AS TableName, DateAdded, COUNT(DateAdded) AS Count
FROM dbo.policy
GROUP BY DateAdded
UNION
SELECT 'policyTraining' AS TableName, DateAdded, COUNT(DateAdded) AS Count
FROM dbo.policyTraining
GROUP BY DateAdded
UNION
SELECT 'securityAwareness' AS TableName, DateAdded, COUNT(DateAdded) AS Count
FROM dbo.securityAwareness
GROUP BY DateAdded
UNION
SELECT 'vulnHost' AS TableName, DateAdded, COUNT(DateAdded) AS Count
FROM dbo.vulnHost
GROUP BY DateAdded
GO

-- View:    localGroupsMemberships_unwraveled
-- PURPOSE: Examines local group memberships, and lists all users regardless
--          of group membership.
CREATE VIEW [dbo].[localGroupsMemberships_unwraveled]
AS
SELECT
	dbo.localGroupMembership.Hostname
	,dbo.localGroupMembership.groupName AS localGroup
	,'<direct assignment>' AS adGroup
	,adUsers.samAccountName
FROM
	dbo.localGroupMembership 
	INNER JOIN dbo.adUserAccounts AS adUsers ON dbo.localGroupMembership.Member = adUsers.samAccountName
WHERE
	adUsers.samAccountName <> 'Guest'
	AND adUsers.samAccountName <> 'Administrator'
UNION
-- Local Groups
SELECT
	dbo.localGroupMembership.Hostname
	,dbo.localGroupMembership.groupName AS localGroup
	,adGroups.groupName AS adGroup
	,adUsers.samAccountName
FROM
	dbo.adUserAccounts 
	RIGHT OUTER JOIN dbo.adGroupMemberships AS adUsers ON dbo.adUserAccounts.samAccountName = adUsers.samAccountName 
	RIGHT OUTER JOIN dbo.adGroupMemberships AS adGroups ON adUsers.groupName = adGroups.groupName
	RIGHT OUTER JOIN dbo.localGroupMembership ON adGroups.groupName = dbo.localGroupMembership.Member
	RIGHT OUTER JOIN dbo.assets ON dbo.localGroupMembership.Hostname = dbo.assets.Hostname
GO
