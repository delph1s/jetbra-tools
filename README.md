# jetbra tools

[🇨🇳中文](./doc/README_CN.md/#jetbra-tools) | [🇬🇧English](#jetbra-tools)

Related tools for jetbra based on enthusiastic Mr. Big

---

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

## Disclaimer

To all enthusiasts engaged in study and research:

For the purpose of learning and studying the design concepts and principles contained within software, the use of software through installation, display, transmission, or storage without the permission of the copyright owner of the software and without compensation is permitted.

Please be aware that all content resources in this repository are sourced from the internet and are intended for user communication, learning, and research purposes only. Copyright belongs to the original copyright holders. Copyright disputes are unrelated to the author of this repository. Users must not use the downloaded content for commercial or illegal purposes and must delete it within 24 hours; otherwise, the user will bear all consequences.
