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

CREATE TABLE IF NOT EXISTS "User_Attribute" (
    "UserId" VARCHAR(100), 
    "AttributeKey" VARCHAR(50), 
    "AttributeValue" VARCHAR(100), 
    PRIMARY KEY ("UserId", "AttributeKey", "AttributeValue")
);

CREATE TABLE IF NOT EXISTS "User_Role" (
    "UserId" VARCHAR(100),
    "RoleName" VARCHAR(50) REFERENCES "Role"("RoleName"),
    PRIMARY KEY ("UserId", "RoleName")
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

INSERT INTO "User_Attribute" ("UserId", "AttributeKey", "AttributeValue") VALUES 
('jane.smith@firma.de', 'Department', 'IT'),
('john.doe@firma.de', 'Department', 'Sales'),
('hr.boss@firma.de', 'Department', '*')
ON CONFLICT ("UserId", "AttributeKey", "AttributeValue") DO NOTHING;

INSERT INTO "User_Role" ("UserId", "RoleName") VALUES 
('jane.smith@firma.de', 'Standard_User'),
('john.doe@firma.de', 'Standard_User'),
('hr.boss@firma.de', 'HR_Manager')
ON CONFLICT ("UserId", "RoleName") DO NOTHING;

INSERT INTO "Employee" ("Id", "Name", "Department", "AnnualSalary", "BonusGoal") VALUES 
(1, 'Jane Smith', 'IT', 82000, 'System Uptime'),
(2, 'John Doe', 'Sales', 65000, '10% Sales Increase')
ON CONFLICT ("Id") DO NOTHING;

-- Set the sequence to the highest value in case we hardcoded inserted IDs
SELECT setval(pg_get_serial_sequence('"Employee"', 'Id'), coalesce(max("Id"), 1), max("Id") IS NOT null) FROM "Employee";

INSERT INTO "BonusPayment" ("Id", "EmployeeId", "Amount", "Reason") VALUES 
(1, 1, 5000.00, 'Excellent Uptime'),
(2, 2, 3000.00, 'Q1 Target Met')
ON CONFLICT ("Id") DO NOTHING;

-- Set the sequence to the highest value in case we hardcoded inserted IDs
SELECT setval(pg_get_serial_sequence('"BonusPayment"', 'Id'), coalesce(max("Id"), 1), max("Id") IS NOT null) FROM "BonusPayment";


-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

CREATE OR REPLACE FUNCTION has_permission(p_permission VARCHAR) 
RETURNS BOOLEAN 
LANGUAGE sql STABLE 
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM "User_Role" ur
        JOIN "Role_Permission" rp ON rp."RoleName" = ur."RoleName"
        WHERE ur."UserId" = COALESCE(current_setting('app.current_user', true), 'anonymous')
          AND rp."Permission" = p_permission
    );
$$;

CREATE OR REPLACE FUNCTION has_department_access(p_department VARCHAR) 
RETURNS BOOLEAN 
LANGUAGE sql STABLE 
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM "User_Attribute" ua
        WHERE ua."UserId" = COALESCE(current_setting('app.current_user', true), 'anonymous')
          AND ua."AttributeKey" = 'Department'
          AND (ua."AttributeValue" = '*' OR ua."AttributeValue" = p_department)
    );
$$;

CREATE OR REPLACE FUNCTION mask_if_not(val anyelement, condition boolean) 
RETURNS anyelement 
LANGUAGE sql IMMUTABLE 
AS $$
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

-- The secure view for Bonus Payments, demonstrating relationship security
CREATE OR REPLACE VIEW "vw_BonusPayment_Secure" (
    "Id",
    "EmployeeId",
    "Amount",
    "Reason"
) WITH (security_barrier = true) AS
SELECT
    bp."Id",
    bp."EmployeeId",
    
    -- FIELD-LEVEL SECURITY: Only visible if the user has Salary:Read AND department access to the parent Employee
    mask_if_not(bp."Amount", has_permission('Salary:Read') AND has_department_access(e."Department")),
    mask_if_not(bp."Reason", has_permission('Salary:Read') AND has_department_access(e."Department"))

FROM "BonusPayment" bp
JOIN "Employee" e ON bp."EmployeeId" = e."Id"
-- ROW-LEVEL SECURITY: Bonus payments are completely filtered out if the user
-- does not have the "Salary:Read" permission OR lacks access to the employee's department.
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
GRANT SELECT ON "User_Attribute" TO app_user;
GRANT SELECT ON "User_Role" TO app_user;