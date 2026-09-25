# Documentation

Start with the root [README](../README.md) (install and quick start), then:

| Doc | Read it when |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | You want to understand how it works: the boundary, components, key caching, revocation, trust model |
| [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) | You're wiring it into a service, switching to JWKS, protecting sensitive actions, writing tests, or upgrading from `auth_integration` |
| [SECURITY.md](SECURITY.md) | You need the threat model, guarantees, known limits, hardening checklist, audit history, or want to report a vulnerability |
| [PUBLISHING.md](PUBLISHING.md) | You're releasing a version to PyPI (a step-by-step tutorial), or want to consume it safely |
| [CHANGELOG.md](CHANGELOG.md) | You're upgrading and want to know what changed |
| [TESTING_GUIDE.md](TESTING_GUIDE.md) | You're running or extending the test suite |
| [CONTRIBUTING.md](CONTRIBUTING.md) | You're opening a pull request |

Module-level references live next to the code: [`gait_sdk/docs/`](../gait_sdk/docs/).

For the whole platform (Gait + this SDK + Lumen), see Gait's `docs/IDENTITY_PLATFORM.md`.
