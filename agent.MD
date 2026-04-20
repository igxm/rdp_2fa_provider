Rust + Windows Credential Provider 开发任务清单

目标
使用 Rust 实现认证核心，并将 Windows Credential Provider 层保持为薄桥接层。Credential Provider 只负责字段展示、输入采集、事件转发和提交对接；认证模式、状态机、输入校验、错误处理和后端调用统一放在 Rust 核心层。

总体原则
1. 薄 UI 桥接层：COM 回调中不堆业务逻辑。
2. 厚认证核心：认证状态、模式切换、输入校验、错误处理集中管理。
3. 可测试：核心逻辑尽量不依赖 COM，优先支持单元测试。
4. 可演进：先落地最小可用版本，再逐步接入验证码、二次密码、倒计时和真实认证服务。

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
- [ ] 完成验证码模式的最终 Windows 凭据交接策略
  说明：仅靠 Credential Provider 不能在自定义认证成功后直接放行进入系统；需要后续引入自定义 LSA Authentication Package，或在自定义认证成功后再安全地提供系统可接受的 Windows 凭据。
- [x] 完成二次密码模式的提交联动

第六阶段：真实认证服务接入
- [ ] 接入验证码发送接口
- [ ] 接入验证码校验接口
- [ ] 接入二次密码校验接口
- [ ] 加入超时、重试、失败提示
- [ ] 清理敏感信息在内存中的停留

第七阶段：倒计时与异步处理
- [x] 为验证码发送增加倒计时状态
- [x] 增加发码按钮禁用/恢复逻辑
- [x] 通过线程更新倒计时状态
- [x] 将状态变化回传到 UI 刷新逻辑
- [x] 完成跨线程访问 UI 相关 COM 对象的初步安全评估
  结论：当前实现把 `ICredentialProviderCredentialEvents` 带入后台线程并直接调用刷新接口，适合作为 mock/原型验证，但生产环境应优先改为封送回创建该 COM 对象的线程，或改造成由 UI 线程轮询/拉取状态。

第八阶段：工程化与上线准备
- [ ] 统一日志方案
- [ ] 修正 CLSID 与注册配置一致性
- [ ] 在虚拟机中进行注册与登录测试
- [ ] 验证 Windows 10/11 x64 兼容性
- [ ] 补齐异常场景测试

当前执行顺序
1. 完成第五阶段剩余项：验证码模式最终交接策略。
2. 进入第六阶段：真实认证服务接入。
3. 继续第七阶段：跨线程 COM 安全性收敛。
4. 最后执行第八阶段：工程化与上线准备。

最近完成
- 已完成认证核心、UI 视图模型、Provider/Credential 桥接重构。
- 已完成 mock 验证码发送与校验流程。
- 已完成验证码倒计时、发码按钮禁用/恢复和定时刷新。
- 已完成“最终认证模式能力边界”和“跨线程 COM 刷新”技术评估。
