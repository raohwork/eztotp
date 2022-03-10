// `eztotp` is free software: you can redistribute it and/or modify it under
// one of following licenses:
//
// - Mozilla Public License, v. 2.0.
// - GNU Lesser General Public License, either version 3 of the License, or (at
//   your option) any later version.
//
// `eztotp` is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE.

//! Crate eztotp provides a easy-to-use Totp solution, [Totp]. See documentations of the
//! struct for further information.

use google_authenticator::GA_AUTH;
use rand::Rng;
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

/// A ready-to-use TOTP solution.
///
/// It supports some features not directly related to Totp:
///
/// - Scratch code: extra codes that can be used in emergency, which can improve UX.
/// - Forbid code reusing: permits only one successful attempt in single time frame for
///   safety.
///
/// These features require you to save the struct after every successful attempt. To
/// make it easier, [serde::Serialize] and [serde::Deserialize] are derived on it.
///
/// # Disable code reusing in real life
///
/// Don't forget to use exclusive lock in your DB (or whatever you persist the struct) to
/// ensure the load-verify-save process is atomic, or attacker may reuse the code even
/// if you disable code reusing.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Totp {
    secret: String,
    scratch: Vec<String>,
    window: u16,
    reusable: bool,
    last_step: u64,
}

impl Totp {
    /// Creates a new Totp instance.
    ///
    /// # Default parameters
    ///
    /// - Number of scratch codes: 8.
    /// - Code reusing: forbid.
    /// - Delay time (window): 1 second, as suggested in RFC document.
    ///
    /// Some parameters are hard-coded:
    ///
    /// - Secret length: 32 characters (160 bits).
    /// - Size of time frame: 30 seconds.
    /// - Code length: 6 digits.
    /// - Scratch code length: 8 digits.
    #[must_use]
    pub fn new() -> Self {
        Totp {
            secret: google_authenticator::create_secret!(),
            scratch: vec![],
            window: 1,
            reusable: false,
            last_step: 0,
        }
        .with_scratch(8)
    }

    /// Regenerate scratch codes. The codes generated will be 8 digits.
    ///
    /// You may set `num` to `0` to completely disable scratch code.
    #[must_use]
    pub fn with_scratch(mut self, num: usize) -> Self {
        let mut rng = rand::thread_rng();
        let mut scratch = Vec::with_capacity(num);
        for _ in 0..num {
            scratch.push(format!("{:08}", rng.gen_range(0..=99999999) as u64));
        }
        self.scratch = scratch;
        self
    }

    /// Set time window.
    ///
    /// The `window` indicates number of seconds ago that a code may be generated.
    #[must_use]
    pub fn with_window(mut self, window: u16) -> Self {
        self.window = window;
        self
    }

    /// Enable or disable code reusing.
    #[must_use]
    pub fn with_reusable(mut self, reusable: bool) -> Self {
        self.reusable = reusable;
        self
    }

    /// Wraps [Totp::verify_code] to ignore all errors.
    ///
    /// # Scratch example
    ///
    /// ```
    /// use eztotp::Totp;
    ///
    /// let mut totp = Totp::new();
    /// let s_codes = totp.scratch_codes();
    /// assert_eq!(s_codes.len(), 8);
    /// let code = s_codes[0].to_owned();
    /// assert!(totp.verify(&code));
    /// assert_eq!(totp.scratch_codes().len(), 7);
    /// ```
    #[inline]
    #[must_use]
    pub fn verify(&mut self, code: &str) -> bool {
        self.verify_code(code).is_ok()
    }

    /// Checks if provided code is valid.
    ///
    /// For scratch code, used one will be removed.
    ///
    /// If code reusing is disabled, current time frome will be saved.
    ///
    /// # Example
    ///
    /// ```
    /// use eztotp::{Totp, VerifyError};
    ///
    /// let mut totp = Totp::new();
    /// let s_codes = totp.scratch_codes();
    /// assert_eq!(s_codes.len(), 8);
    ///
    /// let code = &"00000000";
    /// let expect = s_codes.contains(code);
    /// let actual = totp.verify_code(code);
    /// match actual {
    ///     Ok(_) => { assert!(expect); }
    ///     Err(err) => {
    ///         assert!(!expect);
    ///         assert_eq!(err, VerifyError::InvalidCode);
    ///     }
    /// }
    /// ```
    pub fn verify_code(&mut self, code: &str) -> Result<(), VerifyError> {
        if code.len() == 8 {
            // check scratch code
            let l = self.scratch.len();
            if l < 1 {
                return Err(VerifyError::InvalidCode);
            }
            self.scratch.retain(|v| v != code);
            if self.scratch.len() != l {
                return Ok(());
            }

            return Err(VerifyError::InvalidCode);
        }

        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(x) => x.as_secs(),
            Err(err) => {
                return Err(VerifyError::Time(err));
            }
        };
        let step = now / 30;

        if !self.reusable && self.last_step == step {
            return Err(VerifyError::CodeUsed);
        }

        let ok = google_authenticator::verify_code!(&self.secret, code, self.window as u64, step);
        if ok && !self.reusable {
            self.last_step = step;
        }

        match ok {
            true => Ok(()),
            _ => Err(VerifyError::InvalidCode),
        }
    }

    /// Generates `otpauth://` uri. You may generate qrcode image with that.
    ///
    /// The generated uri is `othauth://totp/name?secret=secret&issuer=issuer`.
    #[inline]
    #[must_use]
    pub fn uri(&self, name: &str, issuer: &str) -> String {
        format!(
            "otpauth://totp/{}?secret={}&issuer={}",
            name, &self.secret, issuer
        )
    }

    /// Get secret.
    ///
    /// Though [Totp::uri] is provided, some users might need to input secret by hand. This
    /// method is used for that.
    #[inline]
    #[must_use]
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// Get scratch codes.
    #[inline]
    #[must_use]
    pub fn scratch_codes(&self) -> Vec<&str> {
        self.scratch.iter().map(|v| v.as_str()).collect()
    }
}

/// Wraps [Totp::new].
impl Default for Totp {
    fn default() -> Self {
        Totp::new()
    }
}

/// Errors reoprted by [Totp::verify_code].
#[derive(Debug)]
pub enum VerifyError {
    /// Failed to get system time.
    Time(SystemTimeError),
    /// Provided code is invalid.
    InvalidCode,
    /// Code is used.
    CodeUsed,
}

impl VerifyError {
    fn as_u8(&self) -> u8 {
        match self {
            VerifyError::Time(_) => 1,
            VerifyError::InvalidCode => 2,
            VerifyError::CodeUsed => 3,
        }
    }
}

impl PartialEq for VerifyError {
    fn eq(&self, other: &Self) -> bool {
        self.as_u8() == other.as_u8()
    }
}
