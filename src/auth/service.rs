pub const MOCK_SMS_CODE: &str = "123456";

// Mock service used during UI and state-machine development.
// The real service will later be replaced with HTTP or IPC calls.
pub struct MockSmsService;

impl MockSmsService {
    pub fn send_code(username: &str) -> Result<&'static str, &'static str> {
        if username.trim().is_empty() {
            Err("发送验证码前请先输入用户名")
        } else {
            Ok(MOCK_SMS_CODE)
        }
    }

    pub fn verify_code(code: &str) -> Result<(), &'static str> {
        if code.trim() == MOCK_SMS_CODE {
            Ok(())
        } else {
            Err("验证码错误，测试码为 123456")
        }
    }
}
