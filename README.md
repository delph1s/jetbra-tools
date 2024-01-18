# jetbra tools

[🇨🇳中文](./doc/README_CN.md/#jetbra-tools) | [🇬🇧English](#jetbra-tools)

---

Related tools for jetbra based on enthusiastic Mr. Big

## Usage

### Extract Information of Valid License

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
