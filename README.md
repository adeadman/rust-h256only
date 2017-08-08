# H256Only

[![crates.io](http://meritbadge.herokuapp.com/h256only)](https://crates.io/crates/h256only)

A Web Token library forked from [rust-jwt](https://github.com/mikkyang/rust-jwt)

Inspired by the [h256only go library](https://github.com/kevinburke/h256only).

For more information on this rationale, please read [Kevin Burke's article on
JWT](https://kev.inburke.com/kevin/things-to-use-instead-of-jwt/?github)

For usage documentation, please see the original JWT
[Documentation](http://mikkyang.github.io/rust-jwt/doc/jwt/index.html).

## Usage

The library provides a `Token` type that wraps a header and claims. The header
and claims can be any types that implement the `Component` trait, which is
automatically implemented for types that implement the `Sized`, `Encodable`,
and `Decodable` traits. See the examples.
