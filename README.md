# 🛡️ Bouncer Admin

> 🚧 🏗️ **Status: Active Development (Pre-Alpha)** 🏗️ 🚧  
> *Bouncer Admin is currently a work in progress. The core policy-as-code controller, OIDC authentication middleware, and embedded UI are actively being built. It is not yet ready for production use.*

Bouncer Admin is the lightweight companion Policy Administration Point (PAP) and visual GUI for Bouncer Engine. Deployed as a secure, single-binary Go application with an embedded single-page application (SPA), it bridges the gap between human administrators and high-performance access control.

This repository serves as the management control plane for the **Dynamic ABAC Engine** [bouncer-engine](https://github.com/casuncio/bouncer-engine).

## Core Features (Planned)

* **Visual Policy Builder:** A structured GUI to craft complex JSON/YAML Attribute-Based Access Control (ABAC) rules without syntax errors.
* **GitOps Policy-as-Code:** Commits all policy mutations directly to a Git repository to act as the immutable, single source of truth.
* **OIDC Authentication:** Secures the admin dashboard using standard OAuth 2.0 Authorization Code Flow with PKCE.
* **Real-Time Redis Sync:** Publishes validated policy updates via Redis Streams to automatically hot-reload distributed engine sidecars without downtime.

## Architecture

* **Language:** Go
* **Frontend:** Embedded SPA served via Go `embed.FS`
* **State Management:** Git (Persistence) & Redis Streams (Distribution)

## Local Testing with Dex

For local OIDC testing, run [Dex](https://github.com/dexidp/dex) with the pre-configured test IdP from `internal/auth/testdata/dex.yaml`.

Start the container from the root of the repo:

```bash
docker run --rm -d \
  --name dex-oidc-test \
  -p 5556:5556 \
  -v "$(pwd)/internal/auth/testdata/dex.yaml":/etc/dex/config.docker.yaml \
  ghcr.io/dexidp/dex:v2.41.0
```

Stop the container:

```bash
docker stop dex-oidc-test
```

The config registers the `bouncer-admin-gui` client (redirect URI `http://localhost:8080/auth/callback`) and a test user: `admin@example.com` / `password`. See `internal/auth/testdata/README.md` for details.

## License

This project is licensed under the Apache 2.0 License - see the `LICENSE` file for details.