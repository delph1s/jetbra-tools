# jetbra tools

[🇨🇳中文](#jetbra-tools) | [🇬🇧English](../README.md/#jetbra-tools)

---

基于热佬开发的 jetbra 的相关工具

## 食用方法

### 提取有效许可证信息

```rust
use cert::jetbra_key::extract_valid_jbkey;

fn main() {
    let jbkey = "<valid jetbra license>";
    match extract_valid_jbkey(jbkey) {
        Ok((id, data)) => {
            println!("License ID: {}", id);
            println!("License Data: {}", data);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
}
```
