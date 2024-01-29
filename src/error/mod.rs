use std::fmt;

/// 使用 #[derive(Debug)] 为 Error 结构体自动派生 Debug trait，
/// 这允许结构体实例使用 {:?} 格式化符号进行打印。
#[derive(Debug)]
pub struct Error {
    // Error 结构体包含一个名为 `details` 的 String 字段，用来存储错误信息。
    details: String,
}

/// 实现 Error 结构体的关联函数和方法。
impl Error {
    /// 关联函数 `new` 用于创建 Error 的新实例。
    /// 它接受一个字符串切片 `msg` 并返回一个 Error 实例。
    pub fn new(msg: &str) -> Error {
        Error {
            // 将传入的字符串切片转换为 String，并存储在 `details` 字段中。
            details: msg.to_string(),
        }
    }
}

/// 为 Error 实现 fmt::Display 特质。
/// 这允许 Error 实例使用 {} 格式化符号进行打印，通常用于用户友好的错误消息显示。
impl fmt::Display for Error {
    /// 实现 fmt 特质的 fmt 方法。
    fn fmt(
        &self,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        // 使用 write! 宏将 Error 的 details 字段输出到提供的 formatter。
        write!(f, "{}", self.details)
    }
}

/// 为 Error 实现 std::error::Error 特质。
/// 这是 Rust 标准库中的错误处理特质，实现它允许与其他 Rust 错误兼容。
impl std::error::Error for Error {
    /// 实现 description 方法来返回错误的描述。
    /// 在这里，它简单地返回存储在 `details` 字段中的字符串。
    fn description(&self) -> &str {
        &self.details
    }
}
