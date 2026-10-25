# When should a product reuse an external account authority through the Identity bridge?

## Problems solved

- Reuses an existing HTTPS login authority while Domainry owns authorization projection for either one personal Workspace per external subject or one shared Workspace per verified external group.

## Business scenarios

- A company already authenticates employees in a central portal and each employee needs one personal Domainry Workspace reused by several installed applications.
- A partner platform presents a credential that must be revalidated against its HTTPS endpoint before Domainry restores the mapped user and Workspace.
- Several verified subjects select the same external group and become distinct Domainry users inside one shared Workspace after server-side membership verification.
- The provider changes a user's display name or email while its stable subject remains unchanged; Domainry updates only the allowed projection and keeps one principal.
- Verification times out, exceeds the response bound, fails a configured JSON Pointer check, or returns an expired credential; no principal or Workspace is partially created.

## Use when

Use the bridge when the external system remains the credential authority, its HTTPS verification response has stable subject mappings, and either one human should reuse a personal Workspace or a verified external group should share one Workspace across applications in an installation.

## Do not use when

Do not use it when Domainry must create passwords, OTP credentials, accounts, or organizations, or when the provider cannot authoritatively verify that the current subject belongs to the selected external group.

## How to adapt

Select the external Identity topology, define the exact verification endpoint and bounded response mappings, keep secrets in environment references, and publish only application role keys that already exist. Treat the external subject ID as provider-scoped identity; do not use an email address as the durable ownership key.

## Adaptation cookbook

| Business requirement | Adapt with | Concrete implementation | Wrong adaptation |
| --- | --- | --- | --- |
| Employees reuse corporate login across several Domainry applications | External Identity bridge plus personal Workspace ownership | Map the verified provider subject to one installation/provider-scoped user and Workspace, then add application-scoped roles on first application access | Creating one Domainry account or Workspace per application |
| Every request must prove the external session is still valid | HTTPS credential verification with bounded response mapping | Revalidate the presented credential, require all configured checks, and map stable subject/display/email fields | Trusting HTTP 200 alone or accepting client-supplied subject IDs |
| Provider changes display name but not subject ID | Projection refresh on the existing provider-scoped subject | Update allowed display/email projection fields and preserve the mapped Principal and personal Workspace | Creating a second user because a mutable label or email changed |
| Verification is slow, oversized, malformed, inactive, or expired | Fail closed before provisioning | Enforce HTTPS, no endpoint credentials/query/fragment, bounded timeout/body, required checks, JSON Pointer mappings, and expiry | Creating the Workspace first and attempting to repair it after verification fails |
| Several partner users collaborate in one shared Workspace | `per_external_group` plus a membership-list verifier | Map the verified external group to one Workspace and each verified subject to a distinct user inside it | Trusting a selector header or merging all members into one Domainry user |

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

If token introspection does not carry mutable profile fields, configure `provider.profile` with its own bounded HTTPS request, credential placement, checks, and JSON Pointer mappings. Profile lookup runs only after token verification. Its mapped subject ID is mandatory and must equal the verified token subject exactly; a mismatch, malformed response, failed check, timeout, redirect, or oversized body fails authentication instead of updating another user's projection.

## Permissions and scope

The bridge authenticates the external subject and projects configured application Roles. It does not let clients choose arbitrary Roles, Workspace IDs, provider subjects, or service headers. Credentials and verification headers remain server-owned.

## Shared Workspace verification

In `per_external_group` mode, the browser client sends the configured selector header on every Runtime request. The selector is only a candidate. After validating the login credential, Bridge calls the configured bounded membership-list endpoint with that same credential and requires an exact Workspace ID match. If the upstream contract requires the identical credential in both a header and cookie, `credential.mirrors` may repeat it into additional header/cookie placements; mirrors cannot introduce another credential or JSON field. Missing membership, duplicate IDs, malformed responses, redirects, timeouts, and oversized bodies fail closed before provisioning.

The membership response may contain provider roles for presentation, but Bridge does not map them to Domainry roles. Every newly provisioned member receives the code-published `initial_role_keys`; application resource roles remain application-owned.

## Boundaries

The external authority owns credentials, login navigation, external groups, invitations, and membership status. Domainry owns the projected principal, application authorization, Workspace lifecycle, and business access enforcement. The bridge does not mutate accounts or memberships in the upstream system.
