Rust + Windows Credential Provider 开发任务清单

目标
使用 Rust 实现认证核心，并将 Windows Credential Provider 层保持为薄桥接层。Credential Provider 负责字段展示、输入采集、事件转发和提交对接；认证模式、状态机、输入校验、错误处理和后端调用统一放在 Rust 核心层。

总体原则
1. 薄 UI 桥接层：COM 回调中不堆业务逻辑。
2. 厚认证核心：认证状态、模式切换、输入校验、错误处理集中管理。
3. 可测试：核心逻辑尽量不依赖 COM，优先支持单元测试。
4. 分层演进：先做 mock 与桥接，再决定最终登录交接方案。

当前关键结论
1. 单靠 Credential Provider 不能在自定义认证成功后直接放行进入系统。
2. 如果要完全不依赖 Windows 原生用户名/密码认证，最终需要自定义 LSA Authentication Package。
3. 如果后端可以在认证成功后返回本机可用账户和密码，则可以把它们包装成 Windows 登录凭据交给 Winlogon。
4. 第 3 条可行，但安全风险高，要求后端能够安全持有并下发本机账户密码，这通常只适合作为过渡方案。

自定义 Authentication Package 方案草图

方案 A：正统方案
1. Credential Provider 采集验证码、二次密码、设备信息等自定义数据。
2. `GetSerialization` 不再构造 `CredPackAuthenticationBufferW` 的用户名/密码缓冲，而是构造“自定义认证包可识别”的二进制序列化数据。
3. `CSampleProvider.rs` 中不再调用 `retrieve_negotiate_auth_package()` 获取 `Negotiate` 包 ID，而是改成获取“自定义 Authentication Package”的包 ID。
4. Winlogon 将序列化结果交给 LSA。
5. 自定义 Authentication Package 解析数据、完成认证、生成系统接受的登录结果。

方案 B：过渡方案
1. Credential Provider 先完成验证码或二次密码校验。
2. 校验成功后，后端返回“本机可登录账户 + 密码”。
3. `GetSerialization` 使用现有 `CredPackAuthenticationBufferW` 路线，将这组账户密码打包成 Windows 可接受的登录凭据。
4. Winlogon 继续走现有 Windows 认证链路。

两种方案对比
1. 方案 A
   - 优点：架构正确，真正满足“自定义认证通过后放行”。
   - 缺点：实现复杂，需要开发和注册自定义 LSA Authentication Package。
2. 方案 B
   - 优点：改造小，可以复用当前 `GetSerialization` 主体逻辑。
   - 缺点：本质仍依赖 Windows 原生账户密码；后端保存或下发本机密码带来较大安全风险。

对当前代码的具体影响

`src/CSampleProvider.rs`
1. 当前 `retrieve_negotiate_auth_package()` 获取的是 `Negotiate` 包 ID。
2. 如果走方案 A：
   - 需要替换为 `retrieve_custom_auth_package()`。
   - 包名改为你们自定义 Authentication Package 的名称。
3. 如果走方案 B：
   - 可以保留“系统包”路线，但更合适的是明确使用 MSV1_0 或 Kerberos 对应的目标包，而不是继续模糊地使用 `Negotiate`。

`src/CSampleCredential.rs`
1. 当前 `GetSerialization()` 的核心逻辑是：
   - 收集用户名/密码
   - 使用 `CredPackAuthenticationBufferW`
   - 返回 Windows 原生可识别的序列化凭据
2. 如果走方案 A：
   - 这段实现要被重写为“自定义序列化格式”。
   - 不再使用 `CredPackAuthenticationBufferW`。
3. 如果走方案 B：
   - 这段实现可以保留总体结构。
   - 但用户名/密码来源改成“自定义认证成功后由接口返回的本机账户密码”。

关于“接口返回本机账户和密码，再构建 Windows 登录凭据”的可行性
1. 技术上可行。
2. 可行前提：
   - 目标机器上确实存在该本机账户。
   - 返回的密码是当前有效密码。
   - 凭据能被当前目标认证包接受。
3. 主要风险：
   - 服务端或中间链路需要保存、传输、下发本机明文密码。
   - 密码轮换、失效、缓存一致性都很麻烦。
   - 一旦后端或传输被攻破，等于泄露本机登录口令。
4. 结论：
   - 可作为 PoC 或过渡方案。
   - 不建议作为长期生产方案。

阶段任务

第一阶段：文档与边界收敛
- [x] 明确认证范围
- [x] 明确系统边界
- [x] 明确输入输出协议

第二阶段：认证核心骨架
- [x] 新建 `auth::mode`
- [x] 新建 `auth::state`
- [x] 新建 `auth::action`
- [x] 新建 `auth::error`
- [x] 新建 `auth::session`
- [x] 定义 `AuthMode`
- [x] 定义 `AuthStatus`
- [x] 定义 `AuthAction`
- [x] 定义 `AuthError`
- [x] 定义 `AuthSession`
- [x] 建立状态流转规则
- [x] 增加基础测试

第三阶段：UI 视图模型
- [x] 新建 `ui_model::field_id`
- [x] 新建 `ui_model::field_state`
- [x] 新建 `ui_model::view_state`
- [x] 统一计算字段显隐
- [x] 统一计算按钮文案
- [x] 统一计算错误提示文案
- [x] 让 Credential Provider 读取视图模型

第四阶段：桥接层重构
- [x] 重构 Provider，保留 `SetUsageScenario`
- [x] 重构 Provider，补齐 field descriptor
- [x] 重构 Credential，`SetStringValue` 转发输入到 `AuthSession`
- [x] 重构 Credential，`CommandLinkClicked` 触发模式切换
- [x] 重构 Credential，`SetSelected` 初始化界面状态
- [x] 重构 Credential，`GetSerialization` 从核心层读取提交条件
- [x] 将共享状态升级为 `AuthSession`
- [x] 增加 UI 刷新逻辑，支持字段状态和文案主动更新

第五阶段：最小可用认证流程
- [x] 接入 mock 认证服务
- [x] 跑通双模式界面
- [x] 完成 mock 验证码发送流程
- [x] 完成 mock 验证码校验流程
- [x] 完成二次密码模式的提交联动
- [x] 完成验证码倒计时、发码按钮禁用/恢复

第六阶段：最终登录交接方案决策
- [x] 评估“Credential Provider 直接放行”的不可行性
- [x] 评估跨线程刷新 COM UI 的初步风险
- [x] 完成自定义 Authentication Package 方案草图
- [x] 评估“接口返回本机账户密码，再构建 Windows 凭据”的可行性
- [ ] 选择最终路线：方案 A 或方案 B

第七阶段：如果选择方案 A
- [ ] 定义自定义 Authentication Package 名称与序列化格式
- [ ] 将 `retrieve_negotiate_auth_package()` 替换为 `retrieve_custom_auth_package()`
- [ ] 重写 `GetSerialization()` 为自定义序列化实现
- [ ] 设计并实现自定义 LSA Authentication Package
- [ ] 联调 Winlogon / LSA / Credential Provider 数据流

第八阶段：如果选择方案 B
- [ ] 定义后端返回本机账户密码的接口协议
- [ ] 在验证码和二次密码校验通过后接收本机账户密码
- [ ] 将 `GetSerialization()` 改为使用返回的本机账户密码构造 Windows 登录凭据
- [ ] 增加明文密码在内存中的最短停留与安全擦除
- [ ] 评估密码轮换、缓存失效和后端存储风险

第九阶段：工程化与上线准备
- [ ] 统一日志方案
- [ ] 修正 CLSID 与注册配置一致性
- [ ] 在虚拟机中进行注册与登录测试
- [ ] 验证 Windows 10/11 x64 兼容性
- [ ] 补齐异常场景测试

当前执行顺序
1. 先完成第六阶段最后一项：确认选 A 还是 B。
2. 如果追求长期正确性，进入第七阶段。
3. 如果先做 PoC，进入第八阶段。
4. 最后执行第九阶段。

最近完成
- 已完成认证核心、UI 视图模型、Provider/Credential 桥接重构。
- 已完成 mock 验证码发送与校验流程。
- 已完成验证码倒计时、发码按钮禁用/恢复和定时刷新。
- 已完成“最终认证模式能力边界”和“跨线程 COM 刷新”技术评估。
- 已完成“自定义 Authentication Package”与“本机账户密码回填”两条最终交接路线的方案整理。

2026-04-21 Scheme A execution update
- [x] Final route selected: Scheme A, custom LSA Authentication Package.
- [x] Custom Authentication Package name defined: `Rdp2FaAuthPackage`.
- [x] Registry override defined: `HKLM\SOFTWARE\facewinunlock-tauri\CUSTOM_AUTH_PACKAGE_NAME`.
- [x] Credential Provider package lookup changed from `Negotiate` to custom package lookup.
- [x] Credential Provider `GetSerialization` changed from `CredPackAuthenticationBufferW` to custom binary serialization.
- [x] Added LSA package entry-point skeleton: `SpLsaModeInitialize`, `InitializePackage`, and `LogonUserEx2` payload parsing.
- [x] Code layering updated: custom serialization protocol lives in `auth::package`; LSA adapter lives in `lsa::package`.
- [x] LSA `SpInitialize` callback added to capture `LSA_SECPKG_FUNCTION_TABLE` for future token/profile construction.
- [x] LSA custom payload verification now delegates to auth core before token/profile construction.
- [ ] Implement LSA token/profile construction after custom verification succeeds.
- [x] Register/unregister scripts added for VM-safe LSA Authentication Package testing.
- [ ] Validate Winlogon / LSA / Credential Provider end-to-end data flow in a VM.

Scheme A serialization format v1
- Header: 8 bytes magic `RDP2FA\0\0`.
- Version: little-endian `u16`, currently `1`.
- Mode: little-endian `u16`, `1` means SMS code, `2` means secondary password.
- Fields: four length-prefixed UTF-16LE strings in this order: username, domain, sms_code, secondary_password.
- Field length: little-endian `u32`, counted in UTF-16 code units, without trailing NUL.
