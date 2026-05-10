use thiserror::Error;

/// All error conditions that can occur within the SMRP protocol stack.
///
/// Each variant carries its canonical wire error code (0x00–0x0A) so that
/// error responses can be serialised without an extra mapping table.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SmrpError {
    /// 0x00 — No error; used as a sentinel in wire-level ACKs.
    #[error("no error (0x00)")]
    NoError,

    /// 0x01 — Received packet header is malformed or truncated.
    #[error("malformed packet header (0x01)")]
    MalformedHeader,

    /// 0x02 — Magic bytes do not match `SMRP_MAGIC`.
    #[error("invalid magic bytes (0x02)")]
    InvalidMagic,

    /// 0x03 — Protocol version advertised by the peer is not supported.
    #[error("unsupported protocol version (0x03)")]
    UnsupportedVersion,

    /// 0x04 — Authentication tag verification failed; packet is rejected.
    #[error("authentication failure (0x04)")]
    AuthenticationFailure,

    /// 0x05 — Session referenced by the packet is unknown or has expired.
    #[error("unknown session (0x05)")]
    UnknownSession,

    /// 0x06 — Packet sequence number is outside the acceptable replay window.
    #[error("replay detected (0x06)")]
    ReplayDetected,

    /// 0x07 — Handshake could not be completed within the timeout period.
    #[error("handshake timeout (0x07)")]
    HandshakeTimeout,

    /// 0x08 — Server has reached `MAX_SESSIONS` and cannot accept new sessions.
    #[error("session limit exceeded (0x08)")]
    SessionLimitExceeded,

    /// 0x09 — Payload length field in the header exceeds `MAX_PAYLOAD`.
    #[error("payload too large (0x09)")]
    PayloadTooLarge,

    /// 0x0A — An internal error occurred that is not covered by other codes.
    #[error("internal error (0x0A)")]
    InternalError,
}

impl SmrpError {
    /// Returns the canonical one-byte wire error code for this error.
    #[must_use]
    pub fn wire_code(&self) -> u8 {
        match self {
            Self::NoError => 0x00,
            Self::MalformedHeader => 0x01,
            Self::InvalidMagic => 0x02,
            Self::UnsupportedVersion => 0x03,
            Self::AuthenticationFailure => 0x04,
            Self::UnknownSession => 0x05,
            Self::ReplayDetected => 0x06,
            Self::HandshakeTimeout => 0x07,
            Self::SessionLimitExceeded => 0x08,
            Self::PayloadTooLarge => 0x09,
            Self::InternalError => 0x0A,
        }
    }

    /// Constructs an [`SmrpError`] from a wire error code, returning
    /// [`SmrpError::InternalError`] for any unrecognised byte.
    #[must_use]
    pub fn from_wire_code(code: u8) -> Self {
        match code {
            0x00 => Self::NoError,
            0x01 => Self::MalformedHeader,
            0x02 => Self::InvalidMagic,
            0x03 => Self::UnsupportedVersion,
            0x04 => Self::AuthenticationFailure,
            0x05 => Self::UnknownSession,
            0x06 => Self::ReplayDetected,
            0x07 => Self::HandshakeTimeout,
            0x08 => Self::SessionLimitExceeded,
            0x09 => Self::PayloadTooLarge,
            _ => Self::InternalError,
        }
    }
}

#[cfg(test)]
#[allow(clippy::pedantic)]
mod tests {
    use super::*;

    const ALL_VARIANTS: &[(SmrpError, u8)] = &[
        (SmrpError::NoError, 0x00),
        (SmrpError::MalformedHeader, 0x01),
        (SmrpError::InvalidMagic, 0x02),
        (SmrpError::UnsupportedVersion, 0x03),
        (SmrpError::AuthenticationFailure, 0x04),
        (SmrpError::UnknownSession, 0x05),
        (SmrpError::ReplayDetected, 0x06),
        (SmrpError::HandshakeTimeout, 0x07),
        (SmrpError::SessionLimitExceeded, 0x08),
        (SmrpError::PayloadTooLarge, 0x09),
        (SmrpError::InternalError, 0x0A),
    ];

    #[test]
    fn wire_codes_are_correct() {
        for (variant, expected_code) in ALL_VARIANTS {
            assert_eq!(variant.wire_code(), *expected_code, "{variant}");
        }
    }

    #[test]
    fn wire_code_round_trips() {
        for (variant, code) in ALL_VARIANTS {
            assert_eq!(SmrpError::from_wire_code(*code), *variant);
        }
    }

    #[test]
    fn unknown_wire_code_yields_internal_error() {
        assert_eq!(SmrpError::from_wire_code(0xFF), SmrpError::InternalError);
        assert_eq!(SmrpError::from_wire_code(0x0B), SmrpError::InternalError);
    }

    #[test]
    fn all_11_variants_covered() {
        assert_eq!(ALL_VARIANTS.len(), 11);
    }

    #[test]
    fn display_includes_wire_code() {
        let msg = SmrpError::AuthenticationFailure.to_string();
        assert!(msg.contains("0x04"), "expected wire code in display: {msg}");
    }
}
