use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    // Authorization Errors
    #[error("Unauthorized: only {expected} can perform this action")]
    Unauthorized { expected: String },

    // Channel Lifecycle Errors
    #[error("Channel not found: {channel_id}")]
    ChannelNotFound { channel_id: String },

    #[error("Channel has expired (expiration: {expiration})")]
    ChannelExpired { expiration: u64 },

    #[error("Channel is already closed")]
    ChannelClosed {},

    // Claim Validation Errors (Story 3.4)
    #[error("Invalid signature")]
    InvalidSignature {},

    #[error("Invalid nonce: got {got}, expected > {expected}")]
    InvalidNonce { got: u64, expected: u64 },

    #[error("Insufficient balance: requested {requested}, available {available}")]
    InsufficientBalance { requested: u128, available: u128 },

    #[error("Invalid denomination: expected {expected}, got {got}")]
    InvalidDenom { expected: String, got: String },

    // OpenChannel-specific errors (Story 3.3)
    #[error("Invalid address: {address}")]
    InvalidAddress { address: String },

    #[error("Invalid expiration: {expiration} (current time: {current_time})")]
    InvalidExpiration { expiration: u64, current_time: u64 },

    #[error("Expiration too far in future: {expiration} (max allowed: {max_allowed})")]
    ExpirationTooFar { expiration: u64, max_allowed: u64 },

    #[error("Invalid funds: expected {expected} coin(s), received {received}")]
    InvalidFunds { expected: usize, received: usize },

    #[error("Channel already exists: {channel_id}")]
    ChannelAlreadyExists { channel_id: String },

    // Implementation placeholder
    #[error("Not implemented yet (Story {story})")]
    Unimplemented { story: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_not_found_error() {
        let err = ContractError::ChannelNotFound {
            channel_id: "channel123".to_string(),
        };
        assert_eq!(err.to_string(), "Channel not found: channel123");
    }

    #[test]
    fn test_channel_expired_error() {
        let err = ContractError::ChannelExpired {
            expiration: 12345678,
        };
        assert_eq!(
            err.to_string(),
            "Channel has expired (expiration: 12345678)"
        );
    }

    #[test]
    fn test_channel_closed_error() {
        let err = ContractError::ChannelClosed {};
        assert_eq!(err.to_string(), "Channel is already closed");
    }

    #[test]
    fn test_invalid_signature_error() {
        let err = ContractError::InvalidSignature {};
        assert_eq!(err.to_string(), "Invalid signature");
    }

    #[test]
    fn test_invalid_nonce_error() {
        let err = ContractError::InvalidNonce {
            got: 5,
            expected: 10,
        };
        assert_eq!(err.to_string(), "Invalid nonce: got 5, expected > 10");
    }

    #[test]
    fn test_insufficient_balance_error() {
        let err = ContractError::InsufficientBalance {
            requested: 1000000,
            available: 500000,
        };
        assert_eq!(
            err.to_string(),
            "Insufficient balance: requested 1000000, available 500000"
        );
    }

    #[test]
    fn test_invalid_denom_error() {
        let err = ContractError::InvalidDenom {
            expected: "uakt".to_string(),
            got: "uatom".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Invalid denomination: expected uakt, got uatom"
        );
    }

    #[test]
    fn test_unauthorized_error() {
        let err = ContractError::Unauthorized {
            expected: "cosmos1admin".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Unauthorized: only cosmos1admin can perform this action"
        );
    }
}
