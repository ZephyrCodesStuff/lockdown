# Lockdown

Lockdown is a small Rust utility for encrypting files or folders.

## Features

- **AES-256-GCM encryption**, to secure data with a strong, authenticated cipher.
- **CRC32 checking**, to ensure data integrity.
- **Custom encrypted container**, to store metadata and encrypted data.

## Installation

To install Lockdown, clone the repository and build it using Cargo:

```sh
git clone https://github.com/ZephyrCodesStuff/lockdown.git
cd lockdown
cargo build --release
```

## Usage

To encrypt a file or folder:

```sh
./lockdown encrypt <input_path> <output_path>
```

To decrypt a file or folder:

```sh
./lockdown decrypt <input_path> <output_path>
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the GPL v3 License - see the [LICENSE](LICENSE) file for details.

- You may not use this software for **any** illegal purposes.
- You may not redistribute this software without proper attribution.
  - If you modify this software, you must disclose the changes you made (e.g. releasing the source code).
- You may not use this software for commercial purposes without permission.