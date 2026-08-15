# Source Verification

- Upstream: https://github.com/StackStorm-Exchange/stackstorm-servicenow
- Upstream declared version: `1.0.0`
- Verified revision: `15bc510dc05143562497b9974805ed1fba189885`
- Git description: `v1.0.0-4-g15bc510`
- Revision date: `2021-12-19T07:26:49Z`
- Revision signature: present, but not locally verifiable because the public key is unavailable
- Latest upstream tag: `v1.0.0` at `c63c03820f96d7f6fbc964098298bcb98277a12b`
- Upstream license: Apache License 2.0
- Upstream NOTICE: none at the verified revision
- Upstream runtime dependency: `pysnow==0.6.5`
- API baseline reviewed: ServiceNow Zurich REST API reference on `2026-08-15`

Authoritative API references:

- REST API reference: https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_RESTAPI.html
- Table API: https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html
- Attachment API: https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_AttachmentAPI.html
- OAuth authentication: https://www.servicenow.com/docs/bundle/zurich-platform-security/page/integrate/inbound-rest/concept/c_OAuthAuthentication.html
- Import Set API: https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_ImportSetAPI.html
- Service Catalog API: https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_ServiceCatalogAPI.html

The current documented routes used by this pack are `/api/now/table/{table}`
for Table API CRUD, `/api/now/attachment` for attachment metadata,
`/api/now/attachment/file` for binary upload,
`/api/now/attachment/{sys_id}/file` for binary download,
`/api/now/attachment/{sys_id}` for metadata and delete, and
`/oauth_token.do` for OAuth refresh-token exchange.

The Table and Attachment APIs are unversioned under the stable `/api/now/`
namespace and are subject to instance ACLs, dictionary attributes, business
rules, data policies, plugins, and customizations. Field and state availability
therefore cannot be inferred solely from a family release.

The upstream pack exposes generic `pysnow` operations, attachments, a workflow
that updates changes by display number, and incident assignment workflows. This
adaptation replaces all runtime code with a shared direct HTTP client, uses
`sys_id` for mutations, and adds curated incident, change, CMDB, and directory
surfaces. No upstream Python implementation was copied verbatim.

Import Set and Service Catalog actions were reviewed but omitted. Import Set
staging tables, transform maps, synchronous/asynchronous behavior, and result
contracts are deployment-specific. Catalog ordering also depends on item
variables, user criteria, requested-for policy, and flow/workflow behavior.
Exposing either as a generic action without a concrete, allowlisted deployment
contract would be less safe than using the restricted Table actions or adding a
separately reviewed site-specific action later.
