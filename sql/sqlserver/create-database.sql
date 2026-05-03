-- ======================================================
-- CREATE THE DATABASE
-- ======================================================

USE [master];
GO

IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'ODataSecurityDemo')
BEGIN
    CREATE DATABASE [ODataSecurityDemo];
END
GO

USE [ODataSecurityDemo];
GO

-- ======================================================
-- TABLES
-- ======================================================

IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[Role_Permission]') AND type in (N'U'))
BEGIN
    CREATE TABLE [dbo].[Role] (
        [RoleName] VARCHAR(50) PRIMARY KEY,
        [Description] NVARCHAR(MAX)
    );
END

IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[Role_Permission]') AND type in (N'U'))
BEGIN
    CREATE TABLE [dbo].[Role_Permission] (
        [RoleName] VARCHAR(50) REFERENCES Role(RoleName),
        [Permission] VARCHAR(100),
        PRIMARY KEY (RoleName, Permission)
    );
END

IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[User_Claim]') AND type in (N'U'))
BEGIN
    CREATE TABLE [dbo].[User_Claim] (
        [Id] INT IDENTITY(1,1) PRIMARY KEY,
        [UserId] VARCHAR(100),
        [ClaimType] VARCHAR(50),    -- 'Role', 'Department', 'Permission'
        [ClaimValue] VARCHAR(100),  
        [AuditSource] VARCHAR(50),  -- e.g., 'System_Init', 'AzureAD'
        [AuditReason] NVARCHAR(MAX),
        [GrantedAt] DATETIME2 DEFAULT SYSDATETIME(),
        UNIQUE (UserId, ClaimType, ClaimValue)
    );
END

IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[Employee]') AND type in (N'U'))
BEGIN
CREATE TABLE [dbo].[Employee] (
    [Id] INT IDENTITY(1,1) PRIMARY KEY,
    [Name] NVARCHAR(200) NOT NULL,
    [Department] NVARCHAR(100) NOT NULL,
    [AnnualSalary] DECIMAL(18, 2),
    [BonusGoal] NVARCHAR(2000),
    [Region] NVARCHAR(50) 
);
END

IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[BonusPayment]') AND type in (N'U'))
BEGIN
    CREATE TABLE [dbo].[BonusPayment] (
        [Id] INT IDENTITY(1,1) PRIMARY KEY,
        [EmployeeId] INT NOT NULL FOREIGN KEY REFERENCES [dbo].[Employee]([Id]),
        [Amount] DECIMAL(18, 2) NOT NULL,
        [Reason] NVARCHAR(2000)
    );
END

GO

-- ============================================================================
-- SAMPLE DATA / SEED
-- ============================================================================

IF NOT EXISTS (SELECT 1 FROM Role WHERE RoleName = 'Standard_User')
    INSERT INTO Role (RoleName, Description) VALUES ('Standard_User', 'Normal Employee');

IF NOT EXISTS (SELECT 1 FROM Role WHERE RoleName = 'HR_Manager')
    INSERT INTO Role (RoleName, Description) VALUES ('HR_Manager', 'Human Resources Manager');

IF NOT EXISTS (SELECT 1 FROM Role_Permission WHERE RoleName = 'Standard_User')
    INSERT INTO Role_Permission (RoleName, Permission) VALUES ('Standard_User', 'Employee:Read_Public');

IF NOT EXISTS (SELECT 1 FROM Role_Permission WHERE RoleName = 'HR_Manager')
    INSERT INTO Role_Permission (RoleName, Permission) VALUES 
    ('HR_Manager', 'Employee:Read_Public'),
    ('HR_Manager', 'Salary:Read');

-- Insert claims (Roles and Departments)
IF NOT EXISTS (SELECT 1 FROM User_Claim WHERE UserId = 'jane.smith@firma.de')
BEGIN
    INSERT INTO User_Claim (UserId, ClaimType, ClaimValue, AuditSource, AuditReason) VALUES 
    ('jane.smith@firma.de', 'Department', 'IT', 'System_Init', 'Initial Setup'),
    ('jane.smith@firma.de', 'Role', 'Standard_User', 'System_Init', 'Initial Setup'),
    ('john.doe@firma.de', 'Department', 'Sales', 'System_Init', 'Initial Setup'),
    ('john.doe@firma.de', 'Role', 'Standard_User', 'System_Init', 'Initial Setup'),
    ('hr.boss@firma.de', 'Department', '*', 'System_Init', 'Initial Setup'),
    ('hr.boss@firma.de', 'Role', 'HR_Manager', 'System_Init', 'Initial Setup');
END;

-- Explicitly inserting IDs requires turning on IDENTITY_INSERT
SET IDENTITY_INSERT Employee ON;
IF NOT EXISTS (SELECT 1 FROM Employee WHERE Id = 1)
    INSERT INTO Employee (Id, Name, Department, AnnualSalary, BonusGoal) VALUES 
    (1, 'Jane Smith', 'IT', 82000, 'System Uptime'),
    (2, 'John Doe', 'Sales', 65000, '10% Sales Increase');
SET IDENTITY_INSERT Employee OFF;

SET IDENTITY_INSERT BonusPayment ON;
IF NOT EXISTS (SELECT 1 FROM BonusPayment WHERE Id = 1)
    INSERT INTO BonusPayment (Id, EmployeeId, Amount, Reason) VALUES 
    (1, 1, 5000.00, 'Excellent Uptime'),
    (2, 2, 3000.00, 'Q1 Target Met');
SET IDENTITY_INSERT BonusPayment OFF;

GO

-- ============================================================================
-- EFFECTIVE CLAIMS VIEW
-- ============================================================================

CREATE OR ALTER VIEW vw_Effective_Claims AS
    -- Direct Claims (Overrides, Departments, Base Roles)
    SELECT 
        UserId, 
        ClaimType, 
        ClaimValue,
        AuditSource AS Lineage,
        AuditReason AS Reason
    FROM User_Claim
    
    UNION ALL
    
    -- Inherited Permissions (Exploding the Roles)
    SELECT 
        uc.UserId, 
        'Permission' AS ClaimType, 
        rp.Permission AS ClaimValue,
        'Inherited via Role: ' + uc.ClaimValue AS Lineage, 
        uc.AuditReason AS Reason
    FROM User_Claim uc
    JOIN Role_Permission rp ON rp.RoleName = uc.ClaimValue
    WHERE uc.ClaimType = 'Role';

GO

-- ======================================================
-- CORE SECURITY FUNCTIONS
-- ======================================================

CREATE OR ALTER FUNCTION dbo.has_claim(@p_type VARCHAR(50), @p_value VARCHAR(100))
RETURNS BIT
AS
BEGIN
    RETURN (
        SELECT CASE WHEN EXISTS (
            SELECT 1 FROM vw_Effective_Claims 
            WHERE UserId = ISNULL(CAST(SESSION_CONTEXT(N'app.current_user') AS VARCHAR(100)), 'anonymous')
              AND ClaimType = @p_type 
              AND ClaimValue = @p_value
        ) THEN 1 ELSE 0 END
    );
END;
GO

CREATE OR ALTER FUNCTION dbo.has_permission(@p_permission VARCHAR(100))
RETURNS BIT
AS
BEGIN
    RETURN dbo.has_claim('Permission', @p_permission);
END;
GO

CREATE OR ALTER FUNCTION dbo.has_department_access(@p_department VARCHAR(100))
RETURNS BIT
AS
BEGIN
    RETURN (
        SELECT CASE WHEN 
            dbo.has_claim('Department', '*') = 1 OR 
            dbo.has_claim('Department', @p_department) = 1 
        THEN 1 ELSE 0 END
    );
END;
GO


-- ======================================================
-- SECURE VIEWS
-- ======================================================

CREATE OR ALTER VIEW vw_Employee_Secure AS 
SELECT 
    e.Id, 
    e.Name, 
    e.Department,
    
    -- FIELD-LEVEL SECURITY
    CASE WHEN dbo.has_permission('Salary:Read') = 1 AND dbo.has_department_access(e.Department) = 1 
         THEN e.AnnualSalary ELSE NULL END AS AnnualSalary,
         
    CASE WHEN dbo.has_permission('Salary:Read') = 1 
         THEN e.BonusGoal ELSE NULL END AS BonusGoal

FROM Employee e
-- ROW-LEVEL SECURITY
WHERE dbo.has_permission('Employee:Read_Public') = 1;

GO

CREATE OR ALTER VIEW vw_BonusPayment_Secure AS
SELECT
    bp.Id,
    bp.EmployeeId,
    
    -- FIELD-LEVEL SECURITY
    CASE WHEN dbo.has_permission('Salary:Read') = 1 AND dbo.has_department_access(e.Department) = 1 
         THEN bp.Amount ELSE NULL END AS Amount,
         
    CASE WHEN dbo.has_permission('Salary:Read') = 1 AND dbo.has_department_access(e.Department) = 1 
         THEN bp.Reason ELSE NULL END AS Reason

FROM BonusPayment bp
JOIN Employee e ON bp.EmployeeId = e.Id
-- ROW-LEVEL SECURITY
WHERE dbo.has_permission('Salary:Read') = 1 
  AND dbo.has_department_access(e.Department) = 1;

GO

-- ============================================================================
-- AUDIT FUNCTION
-- ============================================================================

CREATE OR ALTER FUNCTION dbo.fn_audit_user(@p_userid VARCHAR(100))
RETURNS TABLE
AS
RETURN (
    SELECT ClaimType, ClaimValue, Lineage, Reason 
    FROM vw_Effective_Claims
    WHERE UserId = @p_userid
);

GO

-- ======================================================
-- LEAST PRIVILEGE USER SETUP
-- ======================================================

-- Create a login and user for the API Application
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'ODataApiLogin')
BEGIN
    CREATE LOGIN [ODataApiLogin] WITH PASSWORD = 'YourStrong!AppPassword123';
END
GO

IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = 'ODataApiUser')
BEGIN
    CREATE USER [ODataApiUser] FOR LOGIN [ODataApiLogin];
END
GO

-- Grant explicit SELECT access ONLY to the secure views
GRANT SELECT ON vw_Employee_Secure TO [ODataApiUser];
GRANT SELECT ON vw_BonusPayment_Secure TO [ODataApiUser];

-- Grant execution rights to the functions so the views can use them
GRANT EXECUTE ON dbo.has_claim TO [ODataApiUser];
GRANT EXECUTE ON dbo.has_permission TO [ODataApiUser];
GRANT EXECUTE ON dbo.has_department_access TO [ODataApiUser];

-- Grant read access to the metadata tables and views
GRANT SELECT ON Role TO [ODataApiUser];
GRANT SELECT ON Role_Permission TO [ODataApiUser];
GRANT SELECT ON User_Claim TO [ODataApiUser];
GRANT SELECT ON vw_Effective_Claims TO [ODataApiUser];