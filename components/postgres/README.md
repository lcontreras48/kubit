# Cluster-local PostgreSQL component

This component adds a single-instance PostgreSQL database managed by
CloudNativePG for Kubit's users, sessions, source proposals, audit events, and
scan history. The CloudNativePG operator and CRDs must already exist in the
cluster. The component does not install or upgrade the operator.

Create two Secrets in the target namespace before including this component:

- `kubit-db-app`, type `kubernetes.io/basic-auth`, containing `username: kubit`
  and an independently generated `password`. CloudNativePG uses it to create
  the `kubit` database owner and Kubit uses it for connections.
- `kubit-auth-bootstrap`, containing `bootstrap-admin-password`, the initial
  local administrator password of at least 12 characters.

Installations using a secret manager may generate these destination Secrets
through their preferred operator. Keep secret-manager authentication and policy
configuration in the infrastructure repository that owns the cluster.

The bootstrap password is used only when the users table is empty. Restarting
Kubit does not reset an existing administrator. Do not store either Secret in
Git. After the first successful administrator login, rotate the bootstrap
value or remove that Secret; it is not needed while the database already
contains users.

Include the component from an environment overlay only after its Secrets and
storage class have been reviewed:

```yaml
components:
  - ../../components/postgres
```

The `Cluster` deliberately uses one instance and a 5 GiB volume. It uses the
target cluster's default StorageClass unless an environment overlay selects a
different one. It has no database high availability. CloudNativePG can manage recovery and lifecycle,
but backup, restore, and major-version upgrade procedures must still be defined
before production use. Move directly to three instances if database HA becomes
a requirement.

Do not enable this component when the installed CloudNativePG/Kubernetes
combination lacks official upstream support. Kubit must report that condition
as unsupported rather than assuming the operator will be reliable.
