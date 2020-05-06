-- Create Read-Only Account for PowerBI Access
CREATE USER samAccountName for LOGIN [<domain>\<samAccountName>];
EXEC sp_addrolemember 'db_datareader','<samAccountName>';

-- Create DBO Account for Table Creation & Data Imports
CREATE USER samAccountName for LOGIN [<domain>\<samAccountName>];
EXEC sp_addrolemember 'db_owner','<samAccountName>';


