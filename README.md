![Crates.io](https://img.shields.io/crates/v/eztotp)
![docs.rs](https://img.shields.io/docsrs/eztotp)
![Crates.io](https://img.shields.io/crates/l/exztotp)

This crate provides a ready-to-use TOTP solution.

It supports some features not directly related to Totp:

- Scratch code: extra codes that can be used in emergency, which can improve UX.
- Forbid code reusing: permits only one successful attempt in single time frame for
  safety.

These features require you to save the struct after every successful attempt. To
make it easier, [serde::Serialize] and [serde::Deserialize] are derived on it.

##### Disable code reusing in real life

Don't forget to use exclusive lock in your DB (or whatever you persist the struct) to
ensure the load-verify-save process is atomic, or attacker may reuse the code even
if you disable code reusing.

# License

`eztotp` is free software: you can redistribute it and/or modify it under
one of following licenses:

- Mozilla Public License, v. 2.0.
- GNU Lesser General Public License, either version 3 of the License, or (at
  your option) any later version.

`eztotp` is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.

You should have received a copy of the GNU Lesser General Public License and
Mozilla Public License along with `eztotp`. If not, see

- https://www.gnu.org/licenses/
- https://mozilla.org/MPL/2.0/

