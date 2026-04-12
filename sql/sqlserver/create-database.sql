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
-- ABAC META-SCHEMA
-- ======================================================
IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[Role]') AND type in (N'U'))
BEGIN
    CREATE TABLE [dbo].[Role] (
        [RoleName] NVARCHAR(50) PRIMARY KEY,
        [Description] NVARCHAR(MAX)
    );
END

IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[Role_Permission]') AND type in (N'U'))
BEGIN
    CREATE TABLE [dbo].[Role_Permission] (
        [RoleName] NVARCHAR(50) FOREIGN KEY REFERENCES [dbo].[Role]([RoleName]),
        [Permission] NVARCHAR(100),
        PRIMARY KEY ([RoleName], [Permission])
    );
END

IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[User_Role]') AND type in (N'U'))
BEGIN
    CREATE TABLE [dbo].[User_Role] (
        [UserId] NVARCHAR(100),
        [RoleName] NVARCHAR(50) FOREIGN KEY REFERENCES [dbo].[Role]([RoleName]),
        PRIMARY KEY ([UserId], [RoleName])
    );
END

IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[User_Attribute]') AND type in (N'U'))
BEGIN
    CREATE TABLE [dbo].[User_Attribute] (
        [UserId] NVARCHAR(100), 
        [AttributeKey] NVARCHAR(50), 
        [AttributeValue] NVARCHAR(100), 
        PRIMARY KEY ([UserId], [AttributeKey], [AttributeValue])
    );
END

GO

-- ======================================================
-- CORE SECURITY FUNCTIONS
-- ======================================================

-- Check if the current session user has a specific permission
CREATE OR ALTER FUNCTION [dbo].[fn_HasPermission] (@Permission NVARCHAR(100))
RETURNS BIT
AS
BEGIN
    DECLARE @CurrentUserId NVARCHAR(100) = CAST(SESSION_CONTEXT(N'app.current_user') AS NVARCHAR(100));
    
    IF EXISTS (
        SELECT 1 FROM [dbo].[User_Role] ur
        JOIN [dbo].[Role_Permission] rp ON rp.[RoleName] = ur.[RoleName]
        WHERE ur.[UserId] = ISNULL(@CurrentUserId, 'anonymous')
          AND rp.[Permission] = @Permission
    )
        RETURN 1;

    RETURN 0;
END;
GO

-- Check if the current session user has a matching attribute (supports wildcards)
CREATE OR ALTER FUNCTION [dbo].[fn_HasAttrAccess] (@Key NVARCHAR(50), @Val NVARCHAR(100))
RETURNS BIT
AS
BEGIN
    DECLARE @CurrentUserId NVARCHAR(100) = CAST(SESSION_CONTEXT(N'app.current_user') AS NVARCHAR(100));
    
    IF EXISTS (
        SELECT 1 FROM [dbo].[User_Attribute] ua
        WHERE ua.[UserId] = ISNULL(@CurrentUserId, 'anonymous')
          AND ua.[AttributeKey] = @Key
          AND (ua.[AttributeValue] = @Val OR ua.[AttributeValue] = '*')
    )
        RETURN 1;

    RETURN 0;
END;
GO

-- Checks if a user is authorized based on a permission and optional attribute
CREATE OR ALTER FUNCTION [dbo].[fn_Auth] (
    @Permission NVARCHAR(100),
    @AttrKey    NVARCHAR(50) = NULL,
    @AttrValue  NVARCHAR(100) = NULL
)
RETURNS BIT
AS
BEGIN
    -- 1. Must have the base permission
    IF [dbo].[fn_HasPermission](@Permission) = 0
        RETURN 0;

    -- 2. If an attribute check is requested, must have matching attribute
    IF @AttrKey IS NOT NULL AND [dbo].[fn_HasAttrAccess](@AttrKey, @AttrValue) = 0
        RETURN 0;

    RETURN 1;
END;
GO

-- ======================================================
-- APP: TABLES
-- ======================================================
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

-- ======================================================
-- APP: SAMPLE DATA / SEED
-- ======================================================

-- Roles
IF NOT EXISTS (SELECT 1 FROM [dbo].[Role] WHERE [RoleName] = 'Standard_User')
BEGIN
    INSERT INTO [dbo].[Role] ([RoleName], [Description]) VALUES 
    ('Standard_User', 'Normal Employee'),
    ('HR_Manager', 'Human Resources Manager');
END

-- Permissions
IF NOT EXISTS (SELECT 1 FROM [dbo].[Role_Permission] WHERE [RoleName] = 'Standard_User' AND [Permission] = 'Employee:Read_Public')
BEGIN
    INSERT INTO [dbo].[Role_Permission] ([RoleName], [Permission]) VALUES 
    ('Standard_User', 'Employee:Read_Public'),
    ('HR_Manager', 'Employee:Read_Public'),
    ('HR_Manager', 'Salary:Read');
END

-- User Attributes (for the Department context)
IF NOT EXISTS (SELECT 1 FROM [dbo].[User_Attribute] WHERE [UserId] = 'jane.smith@firma.de')
BEGIN
    INSERT INTO [dbo].[User_Attribute] ([UserId], [AttributeKey], [AttributeValue]) VALUES 
    ('jane.smith@firma.de', 'Department', 'IT'),
    ('john.doe@firma.de', 'Department', 'Sales'),
    ('hr.boss@firma.de', 'Department', '*');
END

-- User Roles
IF NOT EXISTS (SELECT 1 FROM [dbo].[User_Role] WHERE [UserId] = 'jane.smith@firma.de')
BEGIN
    INSERT INTO [dbo].[User_Role] ([UserId], [RoleName]) VALUES 
    ('jane.smith@firma.de', 'Standard_User'),
    ('john.doe@firma.de', 'Standard_User'),
    ('hr.boss@firma.de', 'HR_Manager');
END

-- Employees
IF NOT EXISTS (SELECT 1 FROM [dbo].[Employee] WHERE [Id] IN (1, 2))
BEGIN
    SET IDENTITY_INSERT [dbo].[Employee] ON;
    INSERT INTO [dbo].[Employee] ([Id], [Name], [Department], [AnnualSalary], [BonusGoal], [Region]) VALUES 
    (1, 'Jane Smith', 'IT', 82000, 'System Uptime', 'North'),
    (2, 'John Doe', 'Sales', 65000, '10% Sales Increase', 'South');
    SET IDENTITY_INSERT [dbo].[Employee] OFF;
END

-- Bonus Payments
IF NOT EXISTS (SELECT 1 FROM [dbo].[BonusPayment] WHERE [Id] IN (1, 2))
BEGIN
    SET IDENTITY_INSERT [dbo].[BonusPayment] ON;
    INSERT INTO [dbo].[BonusPayment] ([Id], [EmployeeId], [Amount], [Reason]) VALUES 
    (1, 1, 5000.00, 'Excellent Uptime'),
    (2, 2, 3000.00, 'Q1 Target Met');
    SET IDENTITY_INSERT [dbo].[BonusPayment] OFF;
END
GO

-- ======================================================
-- APP: SECURE VIEWS
-- ======================================================

-- Secure view for Employees
CREATE OR ALTER VIEW [dbo].[vw_Employee_Secure]
AS
SELECT 
    e.[Id], 
    e.[Name], 
    e.[Department],
    
    -- FIELD-LEVEL SECURITY
    -- Mask AnnualSalary if lacks Salary:Read OR lack Department access
    IIF([dbo].[fn_Auth]('Salary:Read', 'Department', e.[Department]) = 1, e.[AnnualSalary], NULL) AS [AnnualSalary],
    
    -- Mask BonusGoal based on base permission
    IIF([dbo].[fn_Auth]('Salary:Read', NULL, NULL) = 1, e.[BonusGoal], NULL) AS [BonusGoal]

FROM [dbo].[Employee] e
-- ROW-LEVEL SECURITY
WHERE [dbo].[fn_Auth]('Employee:Read_Public', NULL, NULL) = 1;
GO

-- Secure view for Bonus Payments with relationship security
CREATE OR ALTER VIEW [dbo].[vw_BonusPayment_Secure]
AS
SELECT
    bp.[Id],
    bp.[EmployeeId],
    
    -- FIELD-LEVEL SECURITY: Only visible if user has Salary:Read AND access to parent Employee's department
    IIF([dbo].[fn_Auth]('Salary:Read', 'Department', e.[Department]) = 1, bp.[Amount], NULL) AS [Amount],
    IIF([dbo].[fn_Auth]('Salary:Read', 'Department', e.[Department]) = 1, bp.[Reason], NULL) AS [Reason]

FROM [dbo].[BonusPayment] bp
JOIN [dbo].[Employee] e ON bp.[EmployeeId] = e.[Id]
-- ROW-LEVEL SECURITY: Bonus payments are filtered out if lacks Salary:Read OR lacks access to the employee's department.
WHERE [dbo].[fn_Auth]('Salary:Read', 'Department', e.[Department]) = 1;
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

-- Grant EXECUTE on the security functions so the views can evaluate them
GRANT EXECUTE ON [dbo].[fn_HasPermission] TO [ODataApiUser];
GRANT EXECUTE ON [dbo].[fn_HasAttrAccess] TO [ODataApiUser];
GRANT EXECUTE ON [dbo].[fn_Auth] TO [ODataApiUser];

-- Grant SELECT ONLY on the secure views
GRANT SELECT ON [dbo].[vw_Employee_Secure] TO [ODataApiUser];
GRANT SELECT ON [dbo].[vw_BonusPayment_Secure] TO [ODataApiUser];

-- Explicitly ensure NO access to the raw tables
DENY SELECT ON [dbo].[Employee] TO [ODataApiUser];
DENY SELECT ON [dbo].[BonusPayment] TO [ODataApiUser];

-- Grant SELECT on metadata tables required for the functions to work
GRANT SELECT ON [dbo].[Role] TO [ODataApiUser];
GRANT SELECT ON [dbo].[Role_Permission] TO [ODataApiUser];
GRANT SELECT ON [dbo].[User_Role] TO [ODataApiUser];
GRANT SELECT ON [dbo].[User_Attribute] TO [ODataApiUser];
GO