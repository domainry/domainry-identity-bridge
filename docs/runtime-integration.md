# Runtime 集成与验收

实现链路为：外部账号系统验证 → Bridge 解析外部主体 → Runtime 宿主事务创建/复用个人 Workspace → Bridge 解析当前应用角色 → SDK Principal / AccessBundle → Runtime 业务鉴权。

## 实现位置

| 项目 | 职责 |
| --- | --- |
| identity-bridge | 提供方配置、验证、持久归属、用户投影、角色与策略、浏览器客户端 |
| identity-sdk | external factory、认证入口扩展、凭证传输扩展、宿主事务接口、组织契约 |
| runtime | 外部安装初始化、个人空间与业务 bootstrap、HTTP 入口、后台 Workspace 传递 |
| plane | `config/modules.json` 外部模式、两个组合模板、交付清单与依赖收敛 |

Runtime 的 `pkg/runtimehost` 生产依赖检查不包含 `domainry-identity/` 实现包。组织交付契约移至 SDK，原 Identity 公共包保留别名以兼容现有使用方。模块模式与 SaaS 模式仍沿用原有认证入口。

## 已执行的验收

- Bridge 单元/持久化测试及 race 检查、go vet、配置校验、浏览器客户端测试。
- SDK 全包测试，包含外部消费者编译。
- Runtime 真实 SQLite 启动及 HTTP 路由：两个测试账号分别开户；并发复用归属；记录/字段/CSV 隔离；伪造 Workspace 拒绝；未创建 Identity 账号表。
- 按现有 Token 校验协议运行 Cookie → Runtime → JSON 校验 → 会话及个人 Workspace 链路，覆盖 HTTP 200 业务错误、账号不可用、refresh 凭证、过期/缺失有效期、错误字段类型，以及大整数用户 ID 的精度。
- 持久归属跨重启、跨应用复用，初始化失败回滚，停用 Workspace 拒绝，后台主体必须明确 Workspace 和角色。
- Plane 外部组合生成与 finalizer 模板、交付/绑定相关测试。
- 交付清单中的 Bridge 身份往返保留；代理拒绝与清单哈希不符的 Bridge 模块内容。
- Runtime 源模块发布测试通过：冻结依赖包、使用独立模块缓存，在 `GOWORK=off` 的消费者中组合 Runtime 与 Bridge 并成功编译；交付内容不保留本地 replace。

测试使用本地 TLS 账号协议服务和测试数据库，不使用线上用户凭证。项目源码验证脚本为 `scripts/verify.sh`。

扩展执行的 Runtime 全模块回归还有现有锁文件漂移失败：Identity 实现/SDK 与 Notification 实现的 `go.mod` 版本和模块锁不一致，Agent / Integration 的能力摘要与模块锁不一致。本次没有修改这些版本或刷新其他模块的摘要；以上外部模式专项验收已通过，不代表整套仓库回归全部通过。

## 当前能力边界

`per_user` 是唯一 Workspace 策略。个人用户不能选企业共享空间，不能用外部响应中的角色、Workspace ID 或权限字段授予内部权限。

个人角色和配置的服务角色必须是应用发布的明确角色。角色定义变更会改变授权 revision，后续请求读取当前目录。已分配角色不会被每次登录的初始配置覆盖。

HTTP 请求每次向外部接口验真；Bridge 不另造长期登录态，也不签发 refresh token。实际退出和撤销语义取决于账号系统：如果原系统退出只清除 Cookie，已复制的 access token 会按原有效期存续。此模块不把清 Cookie 描述为全局令牌撤销。

后台 `PrincipalResolver` 按持久绑定和配置的服务主体解析应用角色，必须显式提供 Workspace。它不是外部会话刷新接口；不持久保存外部凭证。需要长期后台执行的应用应声明独立的 service / system_managed 角色与服务主体。

密码、OTP、组织管理、权限集、业务 profile 绑定及原 Identity 的服务令牌机制不是本适配器提供的能力。角色或 Handler 要求这些能力时失败；其中组织/账号管理 Handler 在外部 Runtime 启动阶段即给出诊断。当前 Notification 使用 module；其 SaaS 方案仍要求原有 Identity SaaS 服务凭证能力。

## 原账号系统适配

复用账号服务现有的 `POST /passport/token/validate`，请求体为 `{"token":"<从 Cookie 或 Header 取得的已有凭证>"}`。本次没有保留任何账号服务改动，也不需要新发账号服务版本。协议根据账号服务远端 main `9b4bdd93e24de4bfd8388e4e25a72d61f4a8c189` 的 `handler/token/token.go` 和调用方远端 main `c9c6b6b49812d3447f21b07db57ccb9ba430039f` 的 `rpc/passport.go` 核对。

成功响应为：

```json
{
  "errCode": 0,
  "errMsg": "success",
  "data": {
    "valid": true,
    "user_id": 9007199254740993,
    "email": "person@example.com",
    "token_type": "access",
    "expires_at": 1900000000
  }
}
```

可用 [Token 校验配置](../examples/token-validation.config.json) 对接，部署时填入实际 HTTPS 地址和业务应用配置。没有额外服务签名头；Cookie 名称、JSON 字段名和响应路径均由配置决定。该接口没有姓名字段，默认使用返回的邮箱作为显示名称，不杜撰字段或增加一次用户信息请求。

账号服务验证 Token、查询用户并判断可用性；Bridge 只接受 `errCode=0`、`valid=true`、`token_type=access` 且尚未过期的响应。账号禁用或 Token 失效后，后续请求不会继续使用之前成功的结果。权限仍由内部应用角色决定。

已用无效测试凭证检查现有线上地址：接口返回 HTTP 200、`errCode=100003`、`data=null`，确认业务码检查必不可少。该检查证明现有接口可达且拒绝无效凭证；正向链路使用本地 TLS 协议服务和真实 Runtime 测试数据库，不能据此声称某个实际业务应用已用真实账号登录。真实账号验收还需要目标应用地址、账号环境及用户完成现有登录流程。
