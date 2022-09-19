## TOTP Generator

Generate time-based one time passcodes in the command line.

Based on the [RFC 6238 Standard](https://www.rfc-editor.org/rfc/rfc6238#page-9)

Getting started:
```
cargo build
cargo run
```

You will be prompted to enter your secret key;
This should be a base32 encoded key (the code that would normally be entered into Authy/ Google Auth App) from your chosen account.

