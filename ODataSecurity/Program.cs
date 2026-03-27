using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.OData;
using Microsoft.AspNetCore.OData.Query;
using Microsoft.AspNetCore.OData.Routing.Controllers;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.OData.ModelBuilder;
using System.Data.Common;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile("appsettings.Development.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables();

// Allow access to HttpContext in services, especially for the CurrentUserService to get the current user's identity.
builder.Services.AddHttpContextAccessor();

// Service used to get the current user's identity. This is crucial for setting the session variable in PostgreSQL for RLS and FLS.
builder.Services.AddScoped<ICurrentUserService, CurrentUserService>();

// The Interceptor for PostgreSQL that sets the session variable with the current user's identity. This
// is registered as Scoped because it needs to be resolved per DbContext instance.
builder.Services.AddScoped<PostgresSecurityInterceptor>();

// Add the DbContext and configure it to use PostgreSQL. The connection string is read from configuration, with a fallback to
// a default value for local development.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? "Host=localhost;Port=54320;Database=ODataSecurityDemo;Username=app_user;Password=app_user";

builder.Services.AddDbContext<AppDbContext>((sp, opt) =>
{
    opt.UseNpgsql(connectionString)
       // The Interceptor is resolved per DbContext instance (Scoped)
       .AddInterceptors(sp.GetRequiredService<PostgresSecurityInterceptor>());
});

// Configure the OData model. We define the entity sets for Employee and BonusPayment. The OData endpoint will be available at /odata.
var odataBuilder = new ODataConventionModelBuilder();

odataBuilder.EntitySet<Employee>("Employees");
odataBuilder.EntitySet<BonusPayment>("BonusPayments");

builder.Services.AddControllers().AddOData(opt => opt
    .Select().Expand().Filter().OrderBy().Count().SetMaxTop(100)
    .AddRouteComponents("odata", odataBuilder.GetEdmModel()));

var app = builder.Build();

// Use a middleware to extract the user identity from the request headers and store it in the HttpContext.Items. This
// allows us to access the current user's identity in the PostgresSecurityInterceptor when setting the session variable
// for RLS and FLS in PostgreSQL.
app.Use(async (context, next) =>
{
    var userId = context.Request.Headers["X-User-Id"].FirstOrDefault() ?? "anonymous";
    context.Items["CurrentUserId"] = userId;
    await next();
});

app.UseRouting();
app.MapControllers();

app.Run();

// ============================================================================
// INFRASTRUCTURE
// ============================================================================

/// <summary>
/// Abstraction for getting the current user identity.
/// </summary>
public interface ICurrentUserService
{
    string GetCurrentUserId();
}

/// <summary>
/// HTTP-specific implementation of the CurrentUserService.
/// </summary>
public class CurrentUserService : ICurrentUserService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public CurrentUserService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public string GetCurrentUserId()
    {
        return _httpContextAccessor.HttpContext?.Items["CurrentUserId"] as string ?? "anonymous";
    }
}


/// <summary>
/// PostgreSQL-specific interceptor that sets a session variable with the current user's identity.
/// </summary>
public class PostgresSecurityInterceptor : DbConnectionInterceptor
{
    private readonly ICurrentUserService _currentUserService;

    public PostgresSecurityInterceptor(ICurrentUserService currentUserService)
    {
        _currentUserService = currentUserService;
    }

    public override async Task ConnectionOpenedAsync(DbConnection connection, ConnectionEndEventData eventData, CancellationToken cancellationToken)
    {
        await SetPostgresSessionVariableAsync(connection, cancellationToken);
    }

    public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
    {
        SetPostgresSessionVariableAsync(connection, CancellationToken.None).GetAwaiter().GetResult();
    }

    private async Task SetPostgresSessionVariableAsync(DbConnection connection, CancellationToken cancellationToken)
    {
        string userId = _currentUserService.GetCurrentUserId();

        // Create a command to set the session variable in PostgreSQL. This variable will be used
        // for RLS and FLS in the database views.
        using DbCommand cmd = connection.CreateCommand();

        // Sets the session variable 'app.current_user' to the current user's ID. This variable is then used in
        // the PostgreSQL views for RLS and FLS.
        cmd.CommandText = "SELECT set_config('app.current_user', @userId, false)";

        // Create and Add the parameter to prevent SQL injection and ensure proper handling of special characters
        DbParameter param = cmd.CreateParameter();
        
        param.ParameterName = "@userId";
        param.Value = userId;
        
        cmd.Parameters.Add(param);

        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }
}

// ============================================================================
// ENTITIES
// ============================================================================

/// <summary>
/// An Employee entity representing an employee in the company. The security for this entity is handled at the 
/// database level through the view 'vw_Employee_Secure', which implements Row-Level Security (RLS) and 
/// Field-Level Security (FLS).
/// </summary>
public class Employee
{
    public int Id { get; set; }
    
    public string Name { get; set; } = null!;

    public string Department { get; set; } = null!;

    public decimal? AnnualSalary { get; set; }

    public string? BonusGoal { get; set; }

    public List<BonusPayment> BonusPayments { get; set; } = [];
}

/// <summary>
/// A BonusPayment entity representing a bonus payment made to an employee. This is related to 
/// the Employee entity via the EmployeeId foreign key. The security for this entity is also 
/// handled at the database level through the view 'vw_BonusPayment_Secure'.
/// </summary>
public class BonusPayment
{
    public int Id { get; set; }

    public int EmployeeId { get; set; }

    public decimal Amount { get; set; }

    public string? Reason { get; set; }

    public Employee? Employee { get; set; }
}

// ============================================================================
// DATABASE
// ============================================================================

/// <summary>
/// DbContext mapping the entities to the secure PostgreSQL views. The views implement Row-Level Security (RLS) and 
/// Field-Level Security (FLS) based on the session variable 'app.current_user' that we set in the 
/// PostgresSecurityInterceptor.
/// </summary>
public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<Employee>().ToTable("vw_Employee_Secure");

        modelBuilder.Entity<BonusPayment>().ToTable("vw_BonusPayment_Secure");

        modelBuilder.Entity<Employee>()
            .HasMany(e => e.BonusPayments)
            .WithOne(b => b.Employee)
            .HasForeignKey(b => b.EmployeeId);
    }
}

// ============================================================================
// ODATA CONTROLLER
// ============================================================================
public class EmployeesController : ODataController
{
    private readonly AppDbContext _context;

    public EmployeesController(AppDbContext context)
    {
        _context = context;
    }

    [HttpGet]
    [EnableQuery]
    public IActionResult Get()
    {
        return Ok(_context.Set<Employee>().AsNoTracking());
    }
}