# verust

Library for data validation in Rust.

It provides validation functions for:

* Email addresses
* URLs
* Phone numbers
* Passwords

## Installation

You can include `verust` library to your project, by adding following to your `Cargo.toml`:

```toml
[dependencies]
verust = "0.1.0"
```

And then do a cargo build:

```bash
cargo build
```

## Usage

First, include the `verust` in your Rust file:

```rust
extern crate verust;
```

Then you can use the validation functions in your code as follows:

For email validation:

```rust
if verust::email::validate("example@example.com") {
    println!("Valid email!");
} else {
    println!("Invalid email.");
}
```

For URL validation:

```rust
if verust::url::validate("https://example.com") {
    println!("Valid URL!");
} else {
    println!("Invalid URL.");
}
```

And alike for other types of validation.

## License

`verust` is distributed under the MIT license. See `LICENSE` file for additional information.

