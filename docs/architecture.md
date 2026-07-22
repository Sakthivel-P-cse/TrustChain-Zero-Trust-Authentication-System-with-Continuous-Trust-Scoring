# TrustChain Architecture & Workflow

## Architecture Diagram

```mermaid
graph TB
    subgraph Client["Clients"]
        USER["Browser / App<br/>(User Auth)"]
        SVC["Service-to-Service<br/>(mTLS)"]
    end

    subgraph WEB["Web Layer"]
        AC["AuthController<br/>POST /auth/token<br/>POST /service-token<br/>GET/POST /api/orders"]
        TAC["TenantAdminController<br/>POST /admin/tenants<br/>DELETE /admin/tenants/{id}<br/>GET /admin/audit"]
    end

    subgraph FILTERS["Security Filter Chain"]
        direction LR
        STF["ServiceTokenFilter<br/>/internal/**"]
        AF["AuthorizationFilter<br/>RBAC + ABAC + Trust"]
        TSF["TrustScoreFilter<br/>Session + Score Gate"]
    end

    subgraph APP["Application Layer"]
        AS["AuthenticationService<br/>tenant→user→pwd→session→JWT"]
        AZ["AuthorizationService<br/>tenant→session→trust→RBAC→ABAC"]
        SS["SessionService<br/>Redis CRUD + termination"]
        STS["ServiceTokenService<br/>issue + validate/consume"]
        TPS["TenantProvisioningService<br/>provision / deprovision / seed"]
    end

    subgraph DOMAIN["Domain Layer"]
        direction TB
        MODELS["Models<br/>Tenant / User / Session<br/>TrustScore / Role / Permission<br/>ServiceIdentity / AuditEvent"]
        POLICY["Policies<br/>TrustScoreEvaluator<br/>RbacEvaluator<br/>AbacEvaluator"]
        PORTS["Ports (Interfaces)<br/>SessionStore / UserRepository<br/>TenantRepository / AuditLogger"]
    end

    subgraph SIGPROV["Signal Providers"]
        IP["IpChangeSignalProvider<br/>-15 on IP change"]
        RATE["RequestRateSignalProvider<br/>-20 on 3× avg spike"]
        FAIL["FailedPermissionSignalProvider<br/>-25 on 3× denials/10min"]
        TRAVEL["ImpossibleTravelSignalProvider<br/>-40 on 500km+ in 6hrs"]
    end

    subgraph INFRA["Infrastructure Layer"]
        RDUMMY["RedisSessionStore<br/>session:{id} / trust:{id}"]
        JDBC["JdbcUserRepository<br/>JdbcTenantRepository<br/>JdbcAuditLogger"]
        ROUTER["TenantSchemaRouter<br/>AbstractRoutingDataSource<br/>SET search_path"]
    end

    subgraph DATA["Data Stores"]
        PG[("PostgreSQL<br/>public: tenants, service_identities, audit_log<br/>per-tenant: users, roles, permissions, role_assignments, abac_rules")]
        RD[("Redis<br/>session & trust state<br/>signal tracking<br/>service JTI replay")]
    end

    subgraph CONFIG["Configuration"]
        SC["SecurityConfig<br/>DI wiring (20+ @Bean)<br/>Filter chains<br/>JWT encoder/decoder"]
    end

    USER -->|"JWT Bearer"| WEB
    SVC -->|"Service Token (mTLS)"| WEB
    WEB --> FILTERS
    FILTERS --> APP
    APP --> DOMAIN
    DOMAIN --> SIGPROV
    DOMAIN --> INFRA
    INFRA --> PG
    INFRA --> RD
    CONFIG -.->|"wires"| FILTERS
    CONFIG -.->|"wires"| APP
    CONFIG -.->|"wires"| SIGPROV
    CONFIG -.->|"wires"| INFRA
```

## Authentication & Authorization Workflow

```mermaid
sequenceDiagram
    participant Client
    participant AuthC as AuthController
    participant AS as AuthenticationService
    participant TRepo as TenantRepository
    participant URepo as UserRepository
    participant SSvc as SessionService
    participant Token as TokenIssuer
    participant Redis
    participant PG as PostgreSQL

    rect rgb(200, 230, 200)
        Note over Client,Token: Step 1: Authentication (Token Issuance)
    end

    Client->>AuthC: POST /auth/token {tenantId, email, password}
    AuthC->>AS: authenticate(tenantId, email, password, remoteAddr)

    AS->>TRepo: findById(tenantId) → public schema
    TRepo-->>AS: Tenant (validate active)

    AS->>PG: SET search_path TO tenant_{id}
    AS->>URepo: findByEmail(email) → tenant schema
    URepo-->>AS: User + roles + permissions

    AS->>PG: findPasswordHash(userId)
    PG-->>AS: bcrypt hash
    AS->>AS: BCrypt.verify(password, hash)

    AS->>SSvc: create(session) → Redis
    SSvc->>Redis: HSET session:{id} fields...
    SSvc->>Redis: HSET trust:{id} score=100
    Redis-->>SSvc: OK

    AS->>Token: issue(claims, 900s, refresh=false)
    Token-->>AS: access JWT
    AS->>Token: issue(claims, 86400s, refresh=true)
    Token-->>AS: refresh JWT

    AS-->>AuthC: TokenResponse {accessToken, refreshToken, expiresIn}
    AuthC-->>Client: 200 {accessToken, refreshToken}

    rect rgb(200, 200, 240)
        Note over Client,Redis: Step 2: Authorized Request (Every API Call)
    end

    Client->>AuthC: GET /api/orders (Authorization: Bearer JWT)

    rect rgb(255, 230, 200)
        Note over AuthC: SecurityFilterChain
    end

    AuthC->>AuthC: JWT Decoder → validate issuer + tokenType=access
    AuthC->>AuthC: JwtAuthenticationConverter → extract roles

    rect rgb(255, 200, 200)
        Note over AuthC: AuthorizationFilter
    end

    AuthC->>AuthC: Extract tenantId, userId, sessionId from JWT
    AuthC->>AuthC: TenantSchemaRouter.useTenant(tenantId)
    AuthC->>AuthC: call AuthorizationService.authorize()

    par Step 2a: Session & Trust Validation
        AuthC->>TRepo: findById(tenantId) → active?
        AuthC->>Redis: HGETALL session:{id}
        AuthC->>Redis: HGETALL trust:{id}
        Redis-->>AuthC: Session + TrustScore
        AuthC->>AuthC: TrustScore < 40? → terminate + 401
        AuthC->>AuthC: TrustScore 40-69 + mutating method? → 403
    and Step 2b: RBAC Evaluation
        AuthC->>AuthC: RbacEvaluator.evaluate(user, requiredPermission)
        AuthC->>AuthC: any role.permissions match? → pass or deny
        alt Denied
            AuthC->>Redis: INCR signal:permission:{sessionId}
            AuthC->>AuthC: setAttribute(permissionDenied=true)
            AuthC-->>Client: 403 {allowed: false, reason: "rbac_denied"}
        end
    and Step 2c: ABAC Evaluation
        AuthC->>AuthC: Load abac_rules → AbacEvaluator
        AuthC->>AuthC: tenant_match rule → cross-tenant check
        AuthC->>AuthC: max_sensitivity rule → clearance check
        AuthC->>AuthC: time_window rule → hours check
        alt Any Denial
            AuthC-->>Client: 403 {reason: "cross_tenant_blocked / clearance_insufficient / outside_allowed_hours"}
        end
    and Step 2d: Trust Score Re-Evaluation
        AuthC->>AuthC: Iterate all TrustSignalProviders
        AuthC->>Redis: signal:ip:{id} → IP change? -15
        AuthC->>Redis: signal:rate:{id} → rate spike? -20
        AuthC->>Redis: signal:permission:{id}→ denials? -25
        AuthC->>Redis: signal:travel:{id}→ impossible travel? -40
        AuthC->>Redis: UPDATE trust:{id} score=newScore
        Redis-->>AuthC: OK
        AuthC->>AuthC: newScore < 40? → terminate + 401
        AuthC->>AuthC: newScore 40-69 + mutating? → 403
    end

    rect rgb(200, 240, 240)
        Note over AuthC: TrustScoreFilter
    end

    AuthC->>AuthC: Re-verify session active + trust score OK
    AuthC->>AuthC: Set header X-TrustChain-Trust-Score

    AuthC-->>Client: 200 [{orders...}, X-TrustChain-Trust-Score header]
```

## Trust Score Lifecycle

```mermaid
stateDiagram-v2
    [*] --> FullAccess : Auth success<br/>score=100

    FullAccess --> ReadOnly : IP change (-15)<br/>Rate spike (-20)<br/>Permission probe (-25)<br/>Impossible travel (-40)
    FullAccess --> FullAccess : Non-anomalous requests<br/>(score stays or recovers)

    ReadOnly --> FullAccess : Re-authentication
    ReadOnly --> Terminated : Additional signals push<br/>score below 40

    Terminated --> FullAccess : Re-authentication only
    Terminated --> [*] : Session destroyed

    note right of ReadOnly
        POST/PUT/PATCH/DELETE
        blocked with 403
    end note

    note right of Terminated
        All requests return 401
        Session flags active=false
    end note
```

## Signal Provider Impact

```mermaid
quadrantChart
    title Trust Signal Severity
    x-axis "Low Frequency" --> "High Frequency"
    y-axis "Low Impact (-5 to -15)" --> "High Impact (-20 to -40)"
    quadrant-1 "Critical: Act Immediately"
    quadrant-2 "Severe: Monitor Closely"
    quadrant-3 "Minor: Log Only"
    quadrant-4 "Moderate: Investigate"
    ImpossibleTravel: [0.2, 0.9]
    FailedPermission: [0.2, 0.7]
    RequestRateSpike: [0.7, 0.6]
    IpChange: [0.6, 0.3]

```

## Key Design Decisions

- **Every request is fully evaluated** — JWT validity alone is insufficient; trust score, RBAC, and ABAC are checked on every API call
- **Schema-per-tenant isolation** — physical PostgreSQL schema separation via `search_path` routing prevents cross-tenant data access at the connection level, enforced by `TenantSchemaRouter`
- **Score recovery is capped** — trust score cannot recover above 80 without re-authentication, preventing score farming
- **Service tokens are single-use** — JTI replay protection via Redis `SETNX` with TTL matching remaining token validity
- **Audit trail** — every auth decision (allowed/denied) is persisted to `audit_log` with session, user, action, resource, outcome, and reason
