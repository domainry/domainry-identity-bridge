# Identity Bridge

复用外部账号系统的登录，向 Runtime 提供标准 Identity SDK Binding。支持每个外部用户一个个人 Workspace，也支持由外部成员关系治理的共享 Workspace；提供方名称、域名、登录/退出入口、凭证方式、响应字段、初始角色和空间名称都由配置决定。

## 已实现

- 通过现有 HTTPS 校验接口验证访问凭证、身份和有效期；每次请求向账号系统重新验证。
- `per_user` 以 `(installation_id, provider_key, external_subject_id)` 唯一归属个人 Workspace。
- `per_external_group` 以 `(installation_id, provider_key, external_workspace_id)` 唯一归属共享 Workspace，并以 `(external_workspace_id, external_subject_id)` 保存 Workspace 内独立用户。
- 共享模式只把客户端 selector 当候选值；Bridge 使用当前用户凭据向配置的成员接口验真。外部 owner/admin/member 字段不会映射成 Domainry 权限。
- Runtime、归属、用户投影、初始角色与业务初始化共用一个宿主事务。唯一键处理并发竞争，失败整体回滚。
- 使用宿主数据库、ORM、迁移锁及唯一 `_schema_migrations`。模块只拥有 `_external_identity_state`，不直接写 Runtime 表。
- 持久权限目录、角色发布、当前用户/角色投影、显式 Workspace 的后台主体解析；业务策略交给 SDK evaluator 执行。
- Runtime 业务路由及模块路由使用同一个外部认证入口。首次外部用户不会获得安装管理员身份。
- Cookie 来源校验、Header 凭证适配、浏览器会话恢复，以及由配置指定的登录/退出跳转。
- Plane 生成和 sourcefinalizer 均支持外部组合，并携带经过交付清单校验的模块依赖。

密码、OTP、账号管理、组织写入与服务令牌签发仍归原账号系统；调用未提供的 SDK 管理能力会明确失败。共享 Workspace 是外部成员关系投影，不会反向修改外部团队，也不会把多个账号合并成同一个 Domainry 用户。

## 接入配置

项目内的 `config/modules.json` 只决定构建时组合：

```json
{"IDENTITY_MODE":"external","NOTIFICATION_MODE":"module"}
```

不要把组合模式放进 Runtime 的运行参数文件。`config/identity-external.json` 保存桥接配置。复用现有账号登录时，从 [Token 校验配置](docs/examples/token-validation.config.json) 复制；[个人配置](docs/examples/personal.config.json) 和 [浏览器配置](docs/examples/browser.config.json) 展示其他提供方的自定义响应与服务凭证用法。组合根默认读取该文件，部署时可以用 `DOMAINRY_IDENTITY_BRIDGE_CONFIG_FILE` 指定其他路径。

```go
IdentityFactory: identitybridge.NewFactory(
    identitybridge.ConfigPathFromEnvironment(), identitybridge.Options{},
),
```

生产配置必须填入真实服务地址与角色。`service_headers` 只引用环境变量，不存放秘密值。不要把示例域名当成已部署服务。共享模式从 [外部组 Workspace 配置](docs/examples/external-group.config.json) 开始，并把 selector、成员列表地址和 JSON Pointer 换成目标账号系统的真实契约。v2 将配置键统一为 `workspace`，并采用组/成员两级持久化；v1 配置会明确拒绝，不做自动迁移。

现有账号服务已经提供 `POST /passport/token/validate`，不需要新增或发布账号接口。此配置将浏览器的 `token` Cookie 作为 JSON `{"token":"<已有登录凭证>"}` 发送给该接口，要求 `/errCode` 等于数字 `0`、`/data/valid` 等于布尔 `true`、`/data/token_type` 等于字符串 `access`，再读取 `/data/user_id` 与 `/data/expires_at`。HTTP 200 本身不代表认证成功。此接口不需要额外的 `service_headers`，Bridge 也不需要账号服务的 JWT 签名密钥。

`browser.credential` 决定浏览器怎样向 Runtime 传凭证；`provider.verification.credential` 决定 Runtime 怎样向账号服务传凭证。这两处独立配置，因此支持 Cookie 进入、JSON 校验。`http_introspection` 是通用 HTTP 验证方式的名称，不要求上游提供同名接口。提供方名称、完整接口 URL、Cookie 名称、请求字段及响应字段均来自配置。若校验接口不返回姓名或邮箱，可配置 `provider.profile` 在验真成功后使用同一凭证查询资料；Bridge 只有在 Profile 的 subject ID 与已验证 subject ID 完全一致时才接受可变展示字段。

外部校验接口需要返回稳定用户 ID、当前有效状态和过期时间。JSON Pointer 指定字段；所有 `checks` 都必须严格匹配。支持 Header / Cookie / POST JSON 向上游发送凭证；不跟随重定向，也不记录令牌和响应体。超过 JavaScript 安全整数范围的用户 ID 保留精度，并作为不透明身份字符串处理。

`installation_id` 与 `provider.key` 是持久命名空间，已有部署不能随意修改。`initial_role_keys` 只在用户首次加入该应用的 Workspace 时生效，后续登录不覆盖已有角色。它是 Domainry 代码发布的固定角色集合，不读取成员响应中的外部角色。角色必须来自应用发布的用户角色目录；不存在或无法解析的角色配置在发布时失败。当前支持直接权限、字段、引用、导出与 guardrail；要求未提供的权限集或业务 profile 绑定会失败，不会忽略后继续授权。

## 浏览器

Runtime 提供三个模块路由：

| 路由 | 用途 |
| --- | --- |
| `GET /auth/external/config` | 公开登录/退出入口和浏览器凭证模式 |
| `GET /auth/external/session` | 验证登录，返回当前用户和当前 Workspace |
| `GET /auth/external/client.js` | 随 Go 模块交付的浏览器客户端 |

```js
import { ExternalIdentityClient } from '/auth/external/client.js'
const auth = new ExternalIdentityClient({
  runtimeURL: location.origin,
  workspace: () => currentExternalGroupID, // 仅 per_external_group 需要
})
const session = await auth.session() // Cookie 模式无需 JavaScript 读取凭证
await auth.authorizedFetch('/records/note')
```

Header 模式传入 `credential: () => existingLoginSDK.accessToken()`；凭证只在请求时读取，不进入浏览器存储。共享模式再传 `workspace()`，客户端按公开配置把当前外部组写入 selector header；服务端仍会查询成员接口，selector 本身没有授权效力。`login()` / `logout()` 跳转到配置的账号系统页面，刷新也由原登录 SDK 负责。客户端不会自动重放业务写入。

Cookie 必须能随请求发送到 Runtime 所在域；跨域时还需配置 Runtime CORS 和凭证策略。浏览器配置中的 `allowed_origins` 必须与实际页面一致；携带 Cookie 的写请求必须提供匹配的 Origin。不同注册域不能靠配置读取彼此的 Cookie，应使用已有登录 SDK 的 Header 凭证方式。可参考 [同源浏览器示例](docs/examples/browser/index.html)。

部署时把配置里的账号地址、应用 origin、应用 key 和角色替换为目标应用的实际值。`login_url` 必须填写已有账号页面实际支持的地址与回跳参数；只有存在可导航的注销页面时才配置可选的 `logout_url`，缺省时客户端明确拒绝注销调用；不要将只接受 POST 的退出 API 当作 GET 跳转页面。账号系统提供凭证，业务应用接入上述客户端后调用 `session()`，才会建立或恢复当前 Workspace。示例页和配置校验不等于已经完成目标业务应用的真实账号登录验收。

## 本地验证与发布

源码验证始终使用各仓库锁定的已发布依赖，并显式设置 `GOWORK=off`；不会创建临时 Go workspace 或本地替换。

```sh
make check
make integration-check
```

可用 `IDENTITY_SDK_REPO_ROOT`、`RUNTIME_REPO_ROOT`、`PLANE_REPO_ROOT` 指定项目位置。发布仓库为 `github.com/domainry/domainry-identity-bridge`（私有），首个版本为 `v0.1.0`，依赖 Identity SDK `v0.1.4`。使用已发布依赖验证时设置 `GOWORK=off`；Runtime 和 Plane 必须选择包含 external 合同的版本。

Runtime 的源模块交付工具已支持 `DOMAINRY_IDENTITY_BRIDGE_REPO_ROOT`，Plane 的 Application Delivery 可携带 `identity_bridge_module`。缺少该模块的旧交付不能完成 external 项目的依赖收敛，会明确报错，不回退到其他身份实现。

验收范围与边界见 [Runtime 接入说明](docs/runtime-integration.md)。
