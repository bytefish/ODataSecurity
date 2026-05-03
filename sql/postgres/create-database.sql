-- ============================================================================
-- TABLE SCHEMA (DDL)
-- ============================================================================
CREATE TABLE IF NOT EXISTS "Role" (
    "RoleName" VARCHAR(50) PRIMARY KEY,
    "Description" TEXT
);

CREATE TABLE IF NOT EXISTS "Role_Permission" (
    "RoleName" VARCHAR(50) REFERENCES "Role"("RoleName"),
    "Permission" VARCHAR(100),
    PRIMARY KEY ("RoleName", "Permission")
);

CREATE TABLE IF NOT EXISTS "User_Claim" (
    "Id" SERIAL PRIMARY KEY,
    "UserId" VARCHAR(100),
    "ClaimType" VARCHAR(50),    
    "ClaimValue" VARCHAR(100),  
    "AuditSource" VARCHAR(50),
    "AuditReason" TEXT,
    "GrantedAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE ("UserId", "ClaimType", "ClaimValue")
);

CREATE TABLE IF NOT EXISTS "Employee" (
    "Id" SERIAL PRIMARY KEY,
    "Name" VARCHAR(200) NOT NULL,
    "Department" VARCHAR(100) NOT NULL,
    "AnnualSalary" DECIMAL(10,2),
    "BonusGoal" TEXT
);

CREATE TABLE IF NOT EXISTS "BonusPayment" (
    "Id" SERIAL PRIMARY KEY,
    "EmployeeId" INTEGER NOT NULL REFERENCES "Employee"("Id"),
    "Amount" DECIMAL(10,2) NOT NULL,
    "Reason" TEXT
);

-- ============================================================================
-- SAMPLE DATA / SEED
-- ============================================================================

INSERT INTO "Role" ("RoleName", "Description") VALUES 
('Standard_User', 'Normal Employee'),
('HR_Manager', 'Human Resources Manager')
ON CONFLICT ("RoleName") DO NOTHING;

INSERT INTO "Role_Permission" ("RoleName", "Permission") VALUES 
('Standard_User', 'Employee:Read_Public'),
('HR_Manager', 'Employee:Read_Public'),
('HR_Manager', 'Salary:Read')
ON CONFLICT ("RoleName", "Permission") DO NOTHING;

-- Insert roles and attributes as unified claims with audit data
INSERT INTO "User_Claim" ("UserId", "ClaimType", "ClaimValue", "AuditSource", "AuditReason") VALUES 
-- Jane Smith (Standard User in IT)
('jane.smith@firma.de', 'Department', 'IT', 'System_Init', 'Initial Setup'),
('jane.smith@firma.de', 'Role', 'Standard_User', 'System_Init', 'Initial Setup'),

-- John Doe (Standard User in Sales)
('john.doe@firma.de', 'Department', 'Sales', 'System_Init', 'Initial Setup'),
('john.doe@firma.de', 'Role', 'Standard_User', 'System_Init', 'Initial Setup'),

-- HR Boss (HR Manager with Global access)
('hr.boss@firma.de', 'Department', '*', 'System_Init', 'Initial Setup'),
('hr.boss@firma.de', 'Role', 'HR_Manager', 'System_Init', 'Initial Setup')
ON CONFLICT ("UserId", "ClaimType", "ClaimValue") DO NOTHING;

INSERT INTO "Employee" ("Id", "Name", "Department", "AnnualSalary", "BonusGoal") VALUES 
(1, 'Jane Smith', 'IT', 82000, 'System Uptime'),
(2, 'John Doe', 'Sales', 65000, '10% Sales Increase')
ON CONFLICT ("Id") DO NOTHING;

SELECT setval(pg_get_serial_sequence('"Employee"', 'Id'), coalesce(max("Id"), 1), max("Id") IS NOT null) FROM "Employee";

INSERT INTO "BonusPayment" ("Id", "EmployeeId", "Amount", "Reason") VALUES 
(1, 1, 5000.00, 'Excellent Uptime'),
(2, 2, 3000.00, 'Q1 Target Met')
ON CONFLICT ("Id") DO NOTHING;

SELECT setval(pg_get_serial_sequence('"BonusPayment"', 'Id'), coalesce(max("Id"), 1), max("Id") IS NOT null) FROM "BonusPayment";

-- ============================================================================
-- EFFECTIVE CLAIMS VIEW
-- ============================================================================
CREATE OR REPLACE VIEW "vw_Effective_Claims" AS
    -- Direct Claims (Overrides, Departments, Base Roles)
    SELECT 
        "UserId", 
        "ClaimType", 
        "ClaimValue",
        "AuditSource" AS "Lineage",
        "AuditReason" AS "Reason"
    FROM "User_Claim"
    
    UNION ALL
    
    -- Inherited Permissions
    SELECT 
        uc."UserId", 
        'Permission' AS "ClaimType", 
        rp."Permission" AS "ClaimValue",
        'Inherited via Role: ' || uc."ClaimValue" AS "Lineage", 
        uc."AuditReason" AS "Reason"
    FROM "User_Claim" uc
    JOIN "Role_Permission" rp ON rp."RoleName" = uc."ClaimValue"
    WHERE uc."ClaimType" = 'Role';

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================
CREATE OR REPLACE FUNCTION has_claim(p_type VARCHAR, p_value VARCHAR) 
RETURNS BOOLEAN LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT EXISTS (
        SELECT 1 FROM "vw_Effective_Claims" 
        WHERE "UserId" = COALESCE(current_setting('app.current_user', true), 'anonymous')
          AND "ClaimType" = p_type 
          AND "ClaimValue" = p_value
    );
$$;

CREATE OR REPLACE FUNCTION has_permission(p_permission VARCHAR) 
RETURNS BOOLEAN LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT has_claim('Permission', p_permission);
$$;

CREATE OR REPLACE FUNCTION has_department_access(p_department VARCHAR) 
RETURNS BOOLEAN LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT has_claim('Department', '*') OR has_claim('Department', p_department);
$$;

CREATE OR REPLACE FUNCTION mask_if_not(val anyelement, condition boolean) 
RETURNS anyelement LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE WHEN condition THEN val ELSE NULL END;
$$;

-- ============================================================================
-- THE SECURE VIEW FOR EF CORE (Anti-Corruption Layer)
-- ============================================================================
CREATE OR REPLACE VIEW "vw_Employee_Secure" (
    "Id", 
    "Name", 
    "Department", 
    "AnnualSalary", 
    "BonusGoal"
) WITH (security_barrier = true) AS 
SELECT 
    e."Id", 
    e."Name", 
    e."Department",
    
    -- FIELD-LEVEL SECURITY
    mask_if_not(e."AnnualSalary", has_permission('Salary:Read') AND has_department_access(e."Department")),
    mask_if_not(e."BonusGoal", has_permission('Salary:Read'))

FROM "Employee" e
-- ROW-LEVEL SECURITY
WHERE has_permission('Employee:Read_Public');

CREATE OR REPLACE VIEW "vw_BonusPayment_Secure" (
    "Id",
    "EmployeeId",
    "Amount",
    "Reason"
) WITH (security_barrier = true) AS
SELECT
    bp."Id",
    bp."EmployeeId",
    
    -- FIELD-LEVEL SECURITY
    mask_if_not(bp."Amount", has_permission('Salary:Read') AND has_department_access(e."Department")),
    mask_if_not(bp."Reason", has_permission('Salary:Read') AND has_department_access(e."Department"))

FROM "BonusPayment" bp
JOIN "Employee" e ON bp."EmployeeId" = e."Id"
-- ROW-LEVEL SECURITY
WHERE has_permission('Salary:Read') AND has_department_access(e."Department");


-- ============================================================================
-- APPLICATION USER & PERMISSIONS (Least Privilege)
-- ============================================================================

DO
$do$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles
      WHERE  rolname = 'app_user') THEN
      CREATE ROLE app_user LOGIN PASSWORD 'app_user';
   END IF;
END
$do$;

-- Grant basic schema access
GRANT USAGE ON SCHEMA public TO app_user;

-- Grant explicit SELECT access ONLY to the secure views
-- The user has NO access to the physical tables "Employee" or "BonusPayment"
GRANT SELECT ON "vw_Employee_Secure" TO app_user;
GRANT SELECT ON "vw_BonusPayment_Secure" TO app_user;

-- Grant read access to the ABAC metadata tables.
-- This is required because the helper functions (has_permission, etc.)
-- are executed in the context of the invoker (SECURITY INVOKER by default).
GRANT SELECT ON "Role" TO app_user;
GRANT SELECT ON "Role_Permission" TO app_user;
GRANT SELECT ON "User_Claim" TO app_user;
GRANT SELECT ON "vw_Effective_Claims" TO app_user;