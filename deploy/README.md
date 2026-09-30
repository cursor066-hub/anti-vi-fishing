# Deployment artifacts are unverified staging templates

The executable, tested route is the local CLI on Node 24.16.0. No container engine, cloud target, service manager, TLS certificate, DNS account or production credentials were available. These files were inspected as configuration text, not applied or validated by systemd/nginx. They do not close production acceptance.

`invariant-engineering.service` assumes a dedicated non-root `invariant` account, reviewed code at `/opt/invariant-fabric`, matching Node at `/usr/bin/node`, private data at `/var/lib/invariant-fabric`, and independently provisioned customer keys. The CLI remains loopback-only and engineering-only. Provisioning is deliberately not an automatic privileged installer.

`nginx-staging.conf` is an HTTPS pattern for a private customer staging hostname. Its hostname/certificate paths are examples, not provisioned resources. Match the app’s `--origin` exactly to the approved HTTPS origin; otherwise the app correctly rejects Host/Origin/CSRF validation. Configure the unit’s ExecStart accordingly after an assigned target exists. Reverse-proxy access/error logging must not contain Authorization, cookies, bodies or query secrets.

The generated bootstrap puts local test custodian keys under its deployment directory. Do not run the gate with access to real custodian private keys. Real independent custody and a separately permissioned production gate require architecture/integration work beyond these templates. Apply no destructive database migration or key rotation from this package.

Production must not proceed merely because a staging service can start. Run the explicit release acceptance gate and preserve rollback evidence, target coverage, security review, customer sign-off, and independently verified key custody first.
