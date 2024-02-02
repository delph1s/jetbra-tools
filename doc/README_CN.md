# jetbra tools

[🇨🇳中文](#jetbra-tools) | [🇬🇧English](../README.md/#jetbra-tools)

基于热佬开发的 jetbra 的相关工具

---

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

## 免责声明

致来各位学习研究爱好者:

为了学习和研究软件内含的设计思想和原理，通过安装、显示、传输或者存储软件等方式使用软件的，可以不经软件著作权人许可，不向其支付报酬。

您需知晓本仓库所有内容资源均来源于网络，仅供用户交流学习与研究使用，版权归属原版权方所有，版权争议与本仓库本作者无关，用户本人下载后不能用作商业或非法用途，需在24小时之内删除，否则后果均由用户承担责任。
