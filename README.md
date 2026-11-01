# RRM — Multi-Tenant Cedar Policy & SurrealDB gRPC Authorization Service

`rrm` is a multi-tenant authorization microservice built in Rust with:
- **[Cedar Policy](https://www.cedarpolicy.com/) (`cedar-policy` v4.14)**: Fast, expressive RBAC and ABAC policy evaluation.
- **[SurrealDB](https://surrealdb.com/) (`surrealdb` v3.2)**: Multi-tenant entity and policy datastore for **Spaces**, **Policies**, **Users**, and generic **Cedar Entities**.
- **[Tonic gRPC](https://github.com/hyperium/tonic) (`tonic` v0.14)**: Strongly-typed gRPC services (`AdminService`, `PolicyService`, `EntityService`, `AuthorizationService`).
- **[`config-rs`](https://crates.io/crates/config) (`config` v0.15)**: Layered configuration in `config/default.toml` with environment variable overrides.

---

## Architecture Overview

```mermaid
flowchart LR
    Admin["RRM Platform Admin"] -->|"gRPC (x-admin-token)\nAdminService"| GrpcServer["Tonic gRPC Server (rrm)"]
    AppAdmin["App Admin / Owner"] -->|"gRPC (x-space-token)\nPolicyService + EntityService"| GrpcServer
    ClientApp["Client App"] -->|"gRPC (x-space-token)\nAuthorizationService"| GrpcServer

    Config["config/default.toml\n+ RRM__* env vars"] --> GrpcServer
    GrpcServer --> Store["SurrealDB Store\n(spaces, policies, users, entities)"]
    GrpcServer --> Engine["Cedar Policy Engine\n(Authorizer + PolicySet + Entities)"]
    Store -->|"Load Space Policies & Entities"| Engine
```

The service separates responsibilities between two personas:
1. **RRM Platform Admin**: Deploys and configures `rrm`, and uses `AdminService` to provision isolated **Spaces** for each application, issuing a unique `api_token` per space.
2. **App Admin (App Owner) & Client Applications**: Uses the space's `api_token` to upload Cedar policies (`PolicyService`), manage `User` and resource entities in SurrealDB (`EntityService`), and evaluate authorization requests (`AuthorizationService`).

---

## Part 1: Guide for the RRM Platform Admin

### 1. Configuration (`config/` folder)

Configuration is loaded using the `config = "0.15"` crate in the following order (later sources override earlier ones):
1. `config/default.toml`
2. `config/local.toml` (optional, git-ignored for local secrets)
3. Custom file path specified by `RRM_CONFIG_PATH` (optional)
4. Environment variables prefixed with `RRM_` and using `__` as nested key separator.

Default [`config/default.toml`](file:///home/c/workspace/rrm/config/default.toml):
```toml
[server]
listen_addr = "0.0.0.0:50051"

[auth]
admin_token = "admin-secret-token"

[surrealdb]
endpoint = "memory"
namespace = "rrm"
database = "authz"
# Optional credentials when connecting to a remote SurrealDB instance (ws:// or http://)
# username = "root"
# password = "root"
```

#### Environment Variable Overrides
| Environment Variable | Config Key | Default | Description |
| :--- | :--- | :--- | :--- |
| `RRM_SERVER__LISTEN_ADDR` | `server.listen_addr` | `0.0.0.0:50051` | Socket address the gRPC server binds to |
| `RRM_AUTH__ADMIN_TOKEN` | `auth.admin_token` | `admin-secret-token` | Secret token required in `x-admin-token` header for `AdminService` |
| `RRM_SURREALDB__ENDPOINT` | `surrealdb.endpoint` | `memory` | SurrealDB connection (`memory`, `ws://host:8000`, `http://host:8000`) |
| `RRM_SURREALDB__NAMESPACE` | `surrealdb.namespace` | `rrm` | SurrealDB namespace |
| `RRM_SURREALDB__DATABASE` | `surrealdb.database` | `authz` | SurrealDB database name |
| `RRM_SURREALDB__USERNAME` | `surrealdb.username` | *(unset)* | Optional root username for remote SurrealDB |
| `RRM_SURREALDB__PASSWORD` | `surrealdb.password` | *(unset)* | Optional root password for remote SurrealDB |

---

### 2. Running the Service

#### Option A: Run Locally with Cargo
```bash
# Run with default config (embedded in-memory SurrealDB)
cargo run

# Or run against an external SurrealDB instance with a custom admin token
RRM_AUTH__ADMIN_TOKEN="prod-admin-secret" \
RRM_SURREALDB__ENDPOINT="ws://127.0.0.1:8000" \
RRM_SURREALDB__USERNAME="root" \
RRM_SURREALDB__PASSWORD="root" \
cargo run --release
```

#### Option B: Build and Run with Docker
The container uses Google Distroless (`gcr.io/distroless/cc-debian12:nonroot`) for minimal attack surface, containing only the runtime dependencies and running as the unprivileged user `nonroot` (UID `65532`).

```bash
# Build the container image
docker build -t rrm:latest .

# Run container with default in-memory SurrealDB (exposing gRPC :50051 and AuthZEN HTTP :8080)
docker run --rm -p 50051:50051 -p 8080:8080 \
  -e RRM_AUTH__ADMIN_TOKEN="prod-admin-secret" \
  rrm:latest
```

#### Option C: Automated Docker Hub Publishing (GitHub Actions)
A GitHub Actions workflow is provided at [`.github/workflows/docker-publish.yml`](.github/workflows/docker-publish.yml) that automatically builds the distroless image and pushes it to Docker Hub on branch pushes, tags, and workflow dispatches.

To enable pushing to your Docker Hub repository:
1. Navigate to your GitHub repository: **Settings** -> **Secrets and variables** -> **Actions**.
2. Add the following repository secrets:
   - `DOCKERHUB_USERNAME`: Your Docker Hub account or organization name.
   - `DOCKERHUB_TOKEN`: A Docker Hub Personal Access Token (PAT) with Read & Write access.


---

### 3. Managing Application Spaces (RRM Admin gRPC Endpoints)

All `rrm.v1.AdminService` calls require the `x-admin-token` gRPC metadata header matching `auth.admin_token`.

#### Create a Space for an Application
When you create a space for an application, `rrm` generates and returns a scoped `api_token` (`rrm_sp_<space_id>_...`). Give this `api_token` and `space_id` to the App Admin.

```bash
grpcurl -plaintext \
  -import-path proto -proto rrm/v1/rrm.proto \
  -H "x-admin-token: admin-secret-token" \
  -d '{
    "space_id": "orders-app",
    "name": "Orders Service",
    "description": "Authorization space for the Orders microservice"
  }' \
  localhost:50051 rrm.v1.AdminService/CreateSpace
```

Example response:
```json
{
  "space": {
    "spaceId": "orders-app",
    "name": "Orders Service",
    "description": "Authorization space for the Orders microservice",
    "createdAt": "1761865200"
  },
  "apiToken": "rrm_sp_orders-app_9f8b7c6d5e4a3b2c1d0e9f8a7b6c5d4e"
}
```

#### List All Spaces
```bash
grpcurl -plaintext \
  -import-path proto -proto rrm/v1/rrm.proto \
  -H "x-admin-token: admin-secret-token" \
  -d '{}' \
  localhost:50051 rrm.v1.AdminService/ListSpaces
```

#### Inspect a Space
```bash
grpcurl -plaintext \
  -import-path proto -proto rrm/v1/rrm.proto \
  -H "x-admin-token: admin-secret-token" \
  -d '{"space_id": "orders-app"}' \
  localhost:50051 rrm.v1.AdminService/GetSpace
```

#### Delete a Space (and all its Policies, Users, and Entities)
```bash
grpcurl -plaintext \
  -import-path proto -proto rrm/v1/rrm.proto \
  -H "x-admin-token: admin-secret-token" \
  -d '{"space_id": "orders-app"}' \
  localhost:50051 rrm.v1.AdminService/DeleteSpace
```

---

## Part 2: Guide for App Admins & Application Developers

Once the RRM Platform Admin creates a Space for your application, you receive:
- `space_id` (e.g., `"orders-app"`)
- `api_token` (e.g., `"rrm_sp_orders-app_..."`)

Pass your token on every gRPC call using either:
- `-H "x-space-token: <api_token>"`
- `-H "authorization: Bearer <api_token>"`

---

### 1. Uploading and Managing Cedar Policies (`PolicyService`)

All Cedar policies are validated for syntax errors before being stored in SurrealDB.

#### Upload a Single Policy (`UpsertPolicy`)
```bash
grpcurl -plaintext \
  -import-path proto -proto rrm/v1/rrm.proto \
  -H "x-space-token: <YOUR_SPACE_API_TOKEN>" \
  -d '{
    "space_id": "orders-app",
    "policy_id": "managers-approve-dept-orders",
    "description": "Managers can approve orders in their own department up to their approval limit",
    "cedar_text": "permit(principal in Role::\"manager\", action == Action::\"approve\", resource is Order) when { principal.department == resource.department && resource.amount <= principal.approval_limit };"
  }' \
  localhost:50051 rrm.v1.PolicyService/UpsertPolicy
```

#### Bulk Upload / Replace Policy Set (`UploadPolicySet`)
Set `"replace_existing": true` to atomically replace all existing policies in your space, or `false` to upsert alongside existing policies:
```bash
grpcurl -plaintext \
  -import-path proto -proto rrm/v1/rrm.proto \
  -H "x-space-token: <YOUR_SPACE_API_TOKEN>" \
  -d '{
    "space_id": "orders-app",
    "replace_existing": true,
    "policies": [
      {
        "policy_id": "managers-approve-dept-orders",
        "description": "Managers can approve orders in their department",
        "cedar_text": "permit(principal in Role::\"manager\", action == Action::\"approve\", resource is Order) when { principal.department == resource.department && resource.amount <= principal.approval_limit };"
      },
      {
        "policy_id": "owners-view-own-orders",
        "description": "Order owners can view their own orders",
        "cedar_text": "permit(principal, action == Action::\"view\", resource is Order) when { resource.owner == principal };"
      },
      {
        "policy_id": "forbid-frozen-orders",
        "description": "Frozen orders cannot be approved",
        "cedar_text": "forbid(principal, action == Action::\"approve\", resource is Order) when { resource.frozen == true };"
      }
    ]
  }' \
  localhost:50051 rrm.v1.PolicyService/UploadPolicySet
```

#### List or Delete Policies
```bash
# List all policies in your space
grpcurl -plaintext \
  -import-path proto -proto rrm/v1/rrm.proto \
  -H "x-space-token: <YOUR_SPACE_API_TOKEN>" \
  -d '{"space_id": "orders-app"}' \
  localhost:50051 rrm.v1.PolicyService/ListPolicies

# Delete a specific policy
grpcurl -plaintext \
  -import-path proto -proto rrm/v1/rrm.proto \
  -H "x-space-token: <YOUR_SPACE_API_TOKEN>" \
  -d '{"space_id": "orders-app", "policy_id": "forbid-frozen-orders"}' \
  localhost:50051 rrm.v1.PolicyService/DeletePolicy
```

---

### 2. Storing Users & Entities in SurrealDB (`EntityService`)

#### Put a User into SurrealDB (`UpsertUser`)
Every User stored via `UpsertUser` is automatically projected into Cedar as `User::"<user_id>"` with:
- Parent entity relationships for every entry in `roles` (`Role::"<role>"`) and `groups` (`Group::"<group>"`), enabling Cedar hierarchy rules like `principal in Role::"manager"` or `principal in Group::"procurement"`.
- Attributes from `email`, `roles`, `groups`, and any custom JSON attributes in `attributes_json`.

```bash
grpcurl -plaintext \
  -import-path proto -proto rrm/v1/rrm.proto \
  -H "x-space-token: <YOUR_SPACE_API_TOKEN>" \
  -d '{
    "space_id": "orders-app",
    "user_id": "alice",
    "email": "alice@acme.example",
    "roles": ["manager"],
    "groups": ["procurement"],
    "attributes_json": "{\"department\": \"logistics\", \"approval_limit\": 5000}"
  }' \
  localhost:50051 rrm.v1.EntityService/UpsertUser
```

#### Query or Delete Users
```bash
# Get a single user
grpcurl -plaintext \
  -import-path proto -proto rrm/v1/rrm.proto \
  -H "x-space-token: <YOUR_SPACE_API_TOKEN>" \
  -d '{"space_id": "orders-app", "user_id": "alice"}' \
  localhost:50051 rrm.v1.EntityService/GetUser

# List all users in the space
grpcurl -plaintext \
  -import-path proto -proto rrm/v1/rrm.proto \
  -H "x-space-token: <YOUR_SPACE_API_TOKEN>" \
  -d '{"space_id": "orders-app"}' \
  localhost:50051 rrm.v1.EntityService/ListUsers
```

#### Put Application Resources / Custom Entities into SurrealDB (`UpsertEntity`)
Use `UpsertEntity` to store resources (`Order`, `Document`, `Project`) or hierarchy nodes (`Group`, `Role`, `Folder`) in SurrealDB.
> **Tip**: To reference another Cedar entity inside `attributes_json` (such as an owner reference), use `{"__entity": {"type": "User", "id": "alice"}}`.

```bash
grpcurl -plaintext \
  -import-path proto -proto rrm/v1/rrm.proto \
  -H "x-space-token: <YOUR_SPACE_API_TOKEN>" \
  -d '{
    "space_id": "orders-app",
    "uid": {"entity_type": "Order", "entity_id": "ord-100"},
    "parents": [],
    "attributes_json": "{\"department\": \"logistics\", \"amount\": 1200, \"frozen\": false, \"owner\": {\"__entity\": {\"type\": \"User\", \"id\": \"alice\"}}}"
  }' \
  localhost:50051 rrm.v1.EntityService/UpsertEntity
```

---

### 3. Evaluating Authorization Requests (`AuthorizationService`)

Your application calls `rrm.v1.AuthorizationService/Authorize` to check whether a `principal` is allowed to perform an `action` on a `resource`. `rrm` automatically loads your space's Cedar policies and SurrealDB entities (Users + Resources) and evaluates the request.

```bash
grpcurl -plaintext \
  -import-path proto -proto rrm/v1/rrm.proto \
  -H "x-space-token: <YOUR_SPACE_API_TOKEN>" \
  -d '{
    "space_id": "orders-app",
    "principal": {"entity_type": "User", "entity_id": "alice"},
    "action": {"entity_type": "Action", "entity_id": "approve"},
    "resource": {"entity_type": "Order", "entity_id": "ord-100"},
    "context_json": "{}"
  }' \
  localhost:50051 rrm.v1.AuthorizationService/Authorize
```

Example response (`ALLOW`):
```json
{
  "allowed": true,
  "decision": "AUTH_DECISION_ALLOW",
  "determiningPolicies": [
    "managers-approve-dept-orders"
  ]
}
```

You can also pass transient `additional_entities` directly in `AuthorizeRequest` for resources that are not persisted in SurrealDB.

---

## 4. OpenID AuthZEN Standard Compliance (HTTP/REST & gRPC)

`rrm` fully implements the **[OpenID Foundation AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html)** standard. Any AuthZEN-compatible Policy Enforcement Point (PEP), API Gateway (e.g., Envoy, Kong, Traefik, Tyk), or language SDK can communicate directly with `rrm`'s Policy Decision Point (PDP).

### Endpoints Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/.well-known/authzen-configuration` | OpenID RFC 8615 metadata discovery document |
| `GET` | `/spaces/{space_id}/.well-known/authzen-configuration` | Tenant-scoped metadata discovery |
| `POST` | `/access/v1/evaluation` | Evaluates a single Subject-Action-Resource-Context (SARC) request |
| `POST` | `/spaces/{space_id}/access/v1/evaluation` | Explicit space-scoped single evaluation |
| `POST` | `/access/v1/evaluations` | Batch evaluates multiple access requests in a single round-trip |
| `POST` | `/spaces/{space_id}/access/v1/evaluations` | Explicit space-scoped batch evaluations |
| `gRPC` | `authzen.authorization.v1.AuthorizationService` | Canonical AuthZEN Protocol Buffers / gRPC service |

---

### Authentication Modes

#### Mode A: Frictionless Testing & Local Development (Zero IdP Dependency)
By default, **no external Identity Provider (IdP) is required** (`auth.oauth.enabled = false`). You can test and operate `rrm` completely offline using your space's API token (`rrm_sp_<space_id>_...`) generated via `CreateSpace`:

```bash
# Pass token via standard Authorization header
-H "Authorization: Bearer rrm_sp_orders-app_..."
```
`rrm` automatically resolves the associated space from the token.

#### Mode B: Optional OAuth 2.0 / OIDC Identity Provider (IdP)
When integrating with an IdP (such as Keycloak, Okta, Auth0, or Entra ID), enable OAuth in `config/default.toml` or via environment variables:

```toml
[auth.oauth]
enabled = true
issuer = "https://idp.example.com/realms/master"
jwks_url = "https://idp.example.com/realms/master/protocol/openid-connect/certs"
audience = "my-application"
space_claim = "space_id" # JWT claim indicating the target space
# secret_or_public_key = "-----BEGIN PUBLIC KEY...-----" # optional static key for testing
```
When enabled, `rrm` validates incoming JWT tokens against the IdP's JWKS. Native space API tokens still work as a fallback so testing remains frictionless.

---

### HTTP / curl Examples

#### 1. Discovery Metadata (`/.well-known/authzen-configuration`)
```bash
curl -s http://localhost:8080/.well-known/authzen-configuration | jq .
```
Response:
```json
{
  "policy_decision_point": "http://localhost:8080",
  "access_evaluation_endpoint": "http://localhost:8080/access/v1/evaluation",
  "access_evaluations_endpoint": "http://localhost:8080/access/v1/evaluations"
}
```

#### 2. Single Access Evaluation (`POST /access/v1/evaluation`)
Evaluates whether a subject is permitted to execute an action on a resource.
> **Note**: Per the AuthZEN specification, access authorization denials return an HTTP `200 OK` with `"decision": false`.

```bash
curl -X POST http://localhost:8080/access/v1/evaluation \
  -H "Authorization: Bearer <YOUR_SPACE_API_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {
      "type": "User",
      "id": "alice",
      "properties": {
        "department": "finance",
        "role": "manager"
      }
    },
    "action": {
      "name": "read"
    },
    "resource": {
      "type": "Document",
      "id": "financial-report-2026",
      "properties": {
        "classification": "confidential",
        "department": "finance"
      }
    },
    "context": {
      "ip_address": "10.0.0.1",
      "network": "internal"
    }
  }' | jq .
```

Permitted Response (`200 OK`):
```json
{
  "decision": true,
  "context": {
    "reason": "Permitted by policies: [\"finance-managers-read\"]",
    "determining_policies": ["finance-managers-read"],
    "errors": []
  }
}
```

Denied Response (`200 OK`):
```json
{
  "decision": false,
  "context": {
    "reason": "Access denied by policy or default deny",
    "determining_policies": [],
    "errors": []
  }
}
```

#### 3. Batch Access Evaluations (`POST /access/v1/evaluations`)
Evaluate multiple authorization decisions in a single round-trip. Common attributes at the root are automatically inherited by individual evaluation items:

```bash
curl -X POST http://localhost:8080/access/v1/evaluations \
  -H "Authorization: Bearer <YOUR_SPACE_API_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {
      "type": "User",
      "id": "alice"
    },
    "context": {
      "network": "internal"
    },
    "evaluations": [
      {
        "id": "eval-doc-1",
        "action": { "name": "read" },
        "resource": {
          "type": "Document",
          "id": "doc-public",
          "properties": { "classification": "public" }
        }
      },
      {
        "id": "eval-doc-2",
        "action": { "name": "read" },
        "resource": {
          "type": "Document",
          "id": "doc-secret",
          "properties": { "classification": "top-secret" }
        }
      },
      {
        "id": "eval-doc-3",
        "action": { "name": "delete" },
        "resource": { "type": "Document", "id": "doc-public" }
      }
    ]
  }' | jq .
```

Response (`200 OK`):
```json
{
  "evaluations": [
    {
      "id": "eval-doc-1",
      "decision": true,
      "context": {
        "reason": "Permitted by policies: [\"permit-public-docs\"]",
        "determining_policies": ["permit-public-docs"],
        "errors": []
      }
    },
    {
      "id": "eval-doc-2",
      "decision": false,
      "context": {
        "reason": "Access denied by policy or default deny"
      }
    },
    {
      "id": "eval-doc-3",
      "decision": false,
      "context": {
        "reason": "Access denied by policy or default deny"
      }
    }
  ]
}
```

---

### AuthZEN gRPC Service

You can also evaluate AuthZEN authorization requests over high-performance gRPC via `proto/authzen/v1/authzen.proto`:

```bash
grpcurl -plaintext \
  -import-path proto -proto authzen/v1/authzen.proto \
  -H "authorization: Bearer <YOUR_SPACE_API_TOKEN>" \
  -d '{
    "space_id": "orders-app",
    "subject": {"type": "User", "id": "alice"},
    "action": {"name": "read"},
    "resource": {"type": "Document", "id": "doc-public"}
  }' \
  localhost:50051 authzen.authorization.v1.AuthorizationService/AccessEvaluation
```

---

## Testing & Verification

Run the unit and end-to-end gRPC integration test suite:
```bash
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```
