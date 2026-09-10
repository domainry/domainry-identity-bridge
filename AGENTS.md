# Development rules

- Read current code before answering architecture questions or changing contracts.
- Keep provider brands, domains, endpoint paths, claim names, credential names, role keys, and workspace naming rules in configuration. Examples must use neutral names and reserved example domains.
- Do not use the Domainry builder skills, worktrees, or additional development branches. Do not launch multiple local instances.
- This module adapts external identity to the existing Identity SDK; it implements the SDK Binding with explicit unsupported account-management capabilities, and does not implement an account/password database.
- Personal ownership is unique by installation, provider, and external subject. Application-specific authorization must not allocate a second personal Workspace.
- Workspace creation, ownership binding, and initial business data must commit atomically through the host. No production in-memory ownership store, process-local uniqueness guarantee, or direct writes to Runtime-owned tables.
- Any future embedded persistence uses domainry-orm and the host's database, transaction, migration lock, and sole `_schema_migrations` ledger.
- Keep access policy evaluation in domainry-identity-sdk. External provider roles and display fields are not authorization grants.
- Never log credentials, response bodies, or resolved secrets. Unknown/incomplete configuration and unverified or mismatched identity fail closed.
- Tests must cover meaningful authentication, scope, provisioning, and configuration boundaries. Packaging-only requests do not authorize additional testing.
