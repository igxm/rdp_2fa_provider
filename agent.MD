Rust + Windows Credential Provider 开发任务清单

目标
使用 Rust 实现认证核心，并将 Windows Credential Provider 层保持为薄桥接层。Credential Provider 负责字段展示、输入采集、事件转发和提交对接；认证模式、状态机、输入校验、错误处理和后端调用统一放在 Rust 核心层。

总体原则
1. 薄 UI 桥接层：COM 回调中不堆业务逻辑。
2. 厚认证核心：认证状态、模式切换、输入校验、错误处理集中管理。
3. 可测试：核心逻辑尽量不依赖 COM，优先支持单元测试。
4. 分层演进：先做 mock 与桥接，再推进最终登录交接方案。
5. 系统级改动只在 VM 中验证，必须保留注册和回滚脚本。

当前关键结论
1. 单靠 Credential Provider 不能在自定义认证成功后直接放行进入系统。
2. 长期正确路线选择方案 A：自定义 LSA Authentication Package。
3. 方案 B（后端返回本机账户密码再打包 Windows 凭据）技术上可行，但安全风险高，仅适合作为 PoC 或过渡方案。
4. 当前代码已进入方案 A：Credential Provider 产出自定义 payload，LSA 包负责解析、验证并最终生成 Windows 可接受的登录结果。

当前代码分层
1. `auth::*`
   - 认证核心、模式、状态机、错误、mock 服务。
   - `auth::package` 定义自定义 Authentication Package 名称和序列化协议。
   - `auth::verification` 负责校验 LSA 收到的自定义 payload。
2. `ui_model::*`
   - 纯 UI 状态计算：字段显隐、交互状态、按钮文案、状态文案。
3. `CSampleProvider.rs` / `CSampleCredential.rs`
   - Windows Credential Provider COM 桥接层。
   - 只负责读取核心状态、刷新 UI、提交序列化结果。
4. `lsa::*`
   - Windows LSA Authentication Package 适配层。
   - 负责 LSA 回调、NTSTATUS、函数表、LSA 分配内存和 token/profile 交接。
5. `scripts::*`
   - VM 中注册/回滚 Credential Provider 和 LSA Authentication Package 的辅助脚本。

方案 A 数据流
1. Credential Provider 采集用户名、验证码或二次密码。
2. `GetSerialization` 生成自定义二进制 payload，不再调用 `CredPackAuthenticationBufferW`。
3. Provider 通过 `retrieve_custom_auth_package()` 查找 `Rdp2FaAuthPackage` 包 ID。
4. Winlogon 将 payload 交给 LSA。
5. LSA 包解析 payload，调用 auth 核心校验。
6. LSA 包构造 profile/token 信息并返回给 Winlogon。

Scheme A serialization format v1
1. Header：8 bytes magic `RDP2FA\0\0`。
2. Version：little-endian `u16`，当前为 `1`。
3. Mode：little-endian `u16`，`1` 表示 SMS code，`2` 表示 secondary password。
4. Fields：四个 length-prefixed UTF-16LE 字符串，顺序为 username、domain、sms_code、secondary_password。
5. Field length：little-endian `u32`，按 UTF-16 code unit 计数，不包含 trailing NUL。

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
- [x] 选择最终路线：方案 A，自定义 LSA Authentication Package

第七阶段：方案 A 实施
- [x] 定义自定义 Authentication Package 名称：`Rdp2FaAuthPackage`
- [x] 定义自定义序列化格式：`auth::package`
- [x] 在注册表配置中加入 `CUSTOM_AUTH_PACKAGE_NAME`
- [x] 将 `retrieve_negotiate_auth_package()` 替换为 `retrieve_custom_auth_package()`
- [x] 重写 `GetSerialization()` 为自定义序列化实现
- [x] 新增 LSA 包入口骨架：`SpLsaModeInitialize`
- [x] 新增 LSA `InitializePackage` 回调并返回包名
- [x] 新增 LSA `SpInitialize` 回调并捕获 `LSA_SECPKG_FUNCTION_TABLE`
- [x] 新增 LSA `LogonUserEx2` payload 解析入口
- [x] LSA payload 校验委托给 `auth::verification`
- [x] 设计 LSA token/profile 构造策略：`docs/lsa_token_profile_strategy.md`
- [x] 实现 LSA profile buffer 构造：`lsa::profile`
- [x] 实现 LSA heap Unicode string 分配 helper，并接入 account/audit string 输出
- [x] 实现 Windows account SID 解析 helper：`lsa::account`
- [x] 实现 `LSA_TOKEN_INFORMATION_V1` 构造 helper：`lsa::token`
- [x] 增加 LSA token 成功路径输出参数和函数表 guard
- [x] 封装 LSA `CreateToken` 调用 wrapper：`lsa::token::create_token_from_v1`
- [x] 实现 LSA token 构造并接入 gated `LogonUserEx2` success path
- [ ] 联调 Winlogon / LSA / Credential Provider 数据流

第八阶段：方案 B（已放弃，仅保留为过渡备选）
- [ ] 定义后端返回本机账户密码的接口协议
- [ ] 在验证码和二次密码校验通过后接收本机账户密码
- [ ] 将 `GetSerialization()` 改为使用返回的本机账户密码构造 Windows 登录凭据
- [ ] 增加明文密码在内存中的最短停留与安全擦除
- [ ] 评估密码轮换、缓存失效和后端存储风险

第九阶段：工程化与上线准备
- [x] 统一基础日志路径配置：`DLL_LOG_PATH`
- [x] 修正 CLSID 与注册配置一致性
- [x] 增加 LSA Authentication Package 注册脚本
- [x] 增加 LSA Authentication Package 回滚脚本
- [x] 增加 VM 注册状态预检脚本：`scripts/test_vm_registration_state.ps1`
- [ ] 在虚拟机中进行注册与登录测试
- [ ] 验证 Windows 10/11 x64 兼容性
- [ ] 补齐异常场景测试
- [x] 梳理发布/安装/回滚操作手册：`docs/vm_validation_checklist.md`

当前执行顺序
1. 完成第七阶段 LSA token/profile 构造策略设计。
2. 根据策略实现 profile buffer 构造。
3. 根据策略实现 token 构造或确定可接受的 LSA token 创建路径。
4. 在 VM 中注册 LSA Authentication Package 并联调完整数据流。
5. 执行 Windows 10/11 x64 兼容性和异常场景测试。

最近完成
- [x] 2026-04-21：完成方案 A 选择，并把 Provider/Credential 从 Windows 原生密码打包切到自定义 payload。
- [x] 2026-04-21：完成 `auth::package` 自定义序列化协议和 round-trip 测试。
- [x] 2026-04-21：完成 LSA 包入口骨架、payload 解析和 auth 核心校验委托。
- [x] 2026-04-21：完成代码分层整理：认证协议在 `auth::package`，LSA 桥接在 `lsa::package`。
- [x] 2026-04-21：完成 LSA 注册/回滚脚本。
- [x] 2026-04-21：完成 VM 注册状态预检脚本和安装/回滚验证清单。
