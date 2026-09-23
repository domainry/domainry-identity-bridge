# When should a product reuse an external account authority through the Identity bridge?

## Problems solved

- Reuses an existing HTTPS login authority while Domainry owns authorization projection and one persistent personal Workspace per external subject.

## Business scenarios

- A company already authenticates employees in a central portal and each employee needs one personal Domainry Workspace reused by several installed applications.
- A partner platform presents a credential that must be revalidated against its HTTPS endpoint before Domainry restores the mapped user and personal Workspace.
- The provider changes a user's display name or email while its stable subject remains unchanged; Domainry updates only the allowed projection and keeps one principal.
- Verification times out, exceeds the response bound, fails a configured JSON Pointer check, or returns an expired credential; no principal or Workspace is partially created.

## Use when

Use the bridge when the external system remains the credential authority, its HTTPS verification response has stable subject mappings, and one human should reuse the same personal Workspace across applications in an installation.

## Do not use when

Do not use it when Domainry must create passwords, OTP credentials, accounts, or organizations, or when several external users must share one externally owned Workspace. Those requirements need a different Identity topology, not looser bridge configuration.

## How to adapt

Select the external Identity topology, define the exact verification endpoint and bounded response mappings, keep secrets in environment references, and publish only application role keys that already exist. Treat the external subject ID as provider-scoped identity; do not use an email address as the durable ownership key.

## Adaptation cookbook

| Business requirement | Adapt with | Concrete implementation | Wrong adaptation |
| --- | --- | --- | --- |
| Employees reuse corporate login across several Domainry applications | External Identity bridge plus personal Workspace ownership | Map the verified provider subject to one installation/provider-scoped user and Workspace, then add application-scoped roles on first application access | Creating one Domainry account or Workspace per application |
| Every request must prove the external session is still valid | HTTPS credential verification with bounded response mapping | Revalidate the presented credential, require all configured checks, and map stable subject/display/email fields | Trusting HTTP 200 alone or accepting client-supplied subject IDs |
| Provider changes display name but not subject ID | Projection refresh on the existing provider-scoped subject | Update allowed display/email projection fields and preserve the mapped Principal and personal Workspace | Creating a second user because a mutable label or email changed |
| Verification is slow, oversized, malformed, inactive, or expired | Fail closed before provisioning | Enforce HTTPS, no endpoint credentials/query/fragment, bounded timeout/body, required checks, JSON Pointer mappings, and expiry | Creating the Workspace first and attempting to repair it after verification fails |
| Several partner users collaborate in one shared Workspace | A separately governed shared-workspace onboarding design | Model explicit shared ownership, membership, and authorization in the owning Identity contract | Reusing the personal Workspace bridge and silently merging distinct subjects |

## Example

For a corporate employee portal, a POST verifier can use this bounded shape (a GET verifier may place the user credential only in an allowed header or cookie):

```json
{
  "kind": "http_introspection",
  "endpoint": "https://accounts.example.com/passport/token/validate",
  "method": "POST",
  "timeout": "3s",
  "max_response_bytes": 65536,
  "credential": {"location": "json", "name": "session_credential"},
  "service_headers": {
    "X-Application-Credential": {"environment": "ACCOUNT_APP_SECRET", "prefix": "Bearer "}
  },
  "response": {
    "subject_id": "/data/subject_id",
    "display_name": "/data/display_name",
    "email": "/data/email",
    "expires_at": "/data/expires_at",
    "expiry_format": "rfc3339",
    "checks": [{"path": "/data/active", "equals": true}]
  }
}
```

The endpoint must be HTTPS without embedded credentials, query, or fragment; method is GET or POST; timeout is 1 ms–30 s; response limit is 1–1,048,576 bytes. JSON credentials require POST. Service headers come only from server environment references and cannot conflict with or replace the user's credential. On first verified access the stable provider subject creates/reuses one `per_user` Workspace; a retry or later application access reuses it. Any failed check, missing pointer, bad expiry, redirect, timeout, or oversized response fails before partial Identity/Workspace creation.

## Permissions and scope

The bridge authenticates the external subject and projects configured application Roles. It does not let clients choose arbitrary Roles, Workspace IDs, provider subjects, or service headers. Credentials and verification headers remain server-owned.

## Boundaries

The external authority owns credentials and login navigation. Domainry owns the projected principal, application authorization, personal Workspace lifecycle, and business access enforcement. The bridge does not implement shared external Workspace ownership or mutate accounts in the upstream system.
