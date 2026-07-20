# AGENTS.md - octavia-operator

## Project overview

octavia-operator is a Kubernetes operator that manages
[OpenStack Octavia](https://docs.openstack.org/octavia/latest/) (the load
balancing service: load balancers, listeners, pools, health monitors, and
amphora VMs) on OpenShift/Kubernetes. It is part of the
[openstack-k8s-operators](https://github.com/openstack-k8s-operators) project.

Key Octavia domain concepts: **load balancers**, **listeners**, **pools**,
**members**, **health monitors**, **amphora** (LB VMs), **amphora
controllers** (health manager, housekeeping, worker), **LB management
networks**, **amphora flavors**, **rsyslog** (amphora log collection).
## Tech stack

| Layer | Technology |
|-------|------------|
| Language | Go (modules, multi-module workspace via `go.work`) |
| Scaffolding | [Kubebuilder v4](https://book.kubebuilder.io/) + [Operator SDK](https://sdk.operatorframework.io/) |
| CRD generation | controller-gen (DeepCopy, CRDs, RBAC, webhooks) |
| Config management | Kustomize |
| Packaging | OLM bundle |
| Testing | Ginkgo/Gomega + envtest (functional), KUTTL (integration) |
| Linting | golangci-lint (`.golangci.yaml`) |
| CI | Prow (`.ci-operator.yaml`), GitHub Actions |

## Custom Resources

| Kind | Purpose |
|------|---------|
| `Octavia` | Top-level CR. Owns the database, keystone service, transport URL, and spawns sub-CRs for each service component. |
| `OctaviaAPI` | Manages the Octavia API deployment. |
| `OctaviaAmphoraController` | Manages the amphora controller services (health manager, housekeeping, worker). |
| `OctaviaRsyslog` | Manages the rsyslog service for amphora log collection. |

The `Octavia` CR has defaulting and validating admission webhooks.
Sub-CRs are created and owned by the `Octavia` controller -- not intended to
be created directly by users.

## Directory structure

**Maintenance rule:** when directories are added, removed, or renamed, or when
their purpose changes, update this table to match.

| Directory | Contents |
|-----------|----------|
| `api/v1beta1/` | CRD types (`octavia_types.go`, `octaviaapi_types.go`, `octaviaamphoracontroller_types.go`, `octaviarsyslog_types.go`), conditions, webhook markers |
| `cmd/` | `main.go` entry point |
| `internal/controller/` | Reconcilers: `octavia_controller.go`, `octaviaapi_controller.go`, `octaviaamphoracontroller_controller.go`, `octaviarsyslog_controller.go` |
| `internal/octavia/` | Octavia-level resource builders (db-sync, common helpers) |
| `internal/octaviaapi/` | OctaviaAPI resource builders |
| `internal/amphoracontrollers/` | OctaviaAmphoraController resource builders |
| `internal/octaviarsyslog/` | OctaviaRsyslog resource builders |
| `internal/webhook/` | Webhook implementation |
| `templates/` | Config files and scripts mounted into pods via `OPERATOR_TEMPLATES` env var |
| `config/crd,rbac,manager,webhook/` | Generated Kubernetes manifests (CRDs, RBAC, deployment, webhooks) |
| `config/samples/` | Example CRs (Kustomize overlays). `network-attachment-definition/` for NAD configuration. |
| `test/functional/` | envtest-based Ginkgo/Gomega tests |
| `test/kuttl/` | KUTTL integration tests |
| `hack/` | Helper scripts (CRD schema checker, local webhook runner) |
| `images/` | Container image resources |
| `install_yamls_setup/` | Ansible playbook for install_yamls setup |

## Build commands

After modifying Go code, always run: `make generate manifests fmt vet`.

## Code style guidelines

- Follow standard openstack-k8s-operators conventions and lib-common patterns.
- Use `lib-common` modules for conditions, endpoints, TLS, storage, and other
  cross-cutting concerns rather than re-implementing them.
- CRD types go in `api/v1beta1/`. Controller logic goes in
  `internal/controller/`. Resource-building helpers go in `internal/octavia*`
  and `internal/amphoracontrollers/` packages matching the CR they support.
- Config templates are plain files in `templates/` -- they are mounted at
  runtime via the `OPERATOR_TEMPLATES` environment variable.
- Webhook logic is split between the kubebuilder markers in `api/v1beta1/` and
  the implementation in `internal/webhook/`.

## Testing

- Functional tests use the envtest framework with Ginkgo/Gomega and live in
  `test/functional/`.
- KUTTL integration tests live in `test/kuttl/`.
- Run all functional tests: `make test`.
- When adding a new field or feature, add corresponding test cases in
  `test/functional/` and update fixture data accordingly.

## Key dependencies

- [lib-common](https://github.com/openstack-k8s-operators/lib-common): shared modules for conditions, endpoints, database, TLS, secrets, etc.
- [infra-operator](https://github.com/openstack-k8s-operators/infra-operator): RabbitMQ and topology APIs.
- [mariadb-operator](https://github.com/openstack-k8s-operators/mariadb-operator): database provisioning.
- [keystone-operator](https://github.com/openstack-k8s-operators/keystone-operator): identity service registration.
- [ovn-operator](https://github.com/openstack-k8s-operators/ovn-operator): OVN networking integration.
- [gophercloud](https://github.com/gophercloud/gophercloud): Go OpenStack SDK.
- [dev-docs/developer.md](https://github.com/openstack-k8s-operators/dev-docs/blob/main/developer.md): developer guide and coding conventions.
