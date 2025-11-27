use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint128};
use cw_storage_plus::Map;

#[cw_serde]
pub struct PaymentChannel {
    pub id: String,
    pub sender: Addr,
    pub recipient: Addr,
    pub amount: Uint128,
    pub denom: String,
    pub expiration: u64,
    pub highest_claim: Uint128,
    pub status: ChannelStatus,
}

#[cw_serde]
pub enum ChannelStatus {
    Open,
    Closed,
    Expired,
}

// Primary storage: channel_id -> PaymentChannel
pub const CHANNELS: Map<&str, PaymentChannel> = Map::new("channels");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_channel_serialization() {
        let channel = PaymentChannel {
            id: "channel123".to_string(),
            sender: Addr::unchecked("sender"),
            recipient: Addr::unchecked("recipient"),
            amount: Uint128::new(1000000),
            denom: "uakt".to_string(),
            expiration: 12345678,
            highest_claim: Uint128::zero(),
            status: ChannelStatus::Open,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&channel).unwrap();

        // Deserialize back
        let restored: PaymentChannel = serde_json::from_str(&json).unwrap();

        assert_eq!(channel, restored);
    }

    #[test]
    fn test_channel_status_variants() {
        assert_ne!(ChannelStatus::Open, ChannelStatus::Closed);
        assert_ne!(ChannelStatus::Open, ChannelStatus::Expired);
        assert_ne!(ChannelStatus::Closed, ChannelStatus::Expired);
    }

    #[test]
    fn test_channel_status_json_format() {
        // Verify snake_case serialization
        let open_json = serde_json::to_string(&ChannelStatus::Open).unwrap();
        assert_eq!(open_json, r#""open""#);

        let closed_json = serde_json::to_string(&ChannelStatus::Closed).unwrap();
        assert_eq!(closed_json, r#""closed""#);

        let expired_json = serde_json::to_string(&ChannelStatus::Expired).unwrap();
        assert_eq!(expired_json, r#""expired""#);
    }

    #[test]
    fn test_empty_string_channel_id() {
        let channel = PaymentChannel {
            id: "".to_string(), // Empty ID edge case
            sender: Addr::unchecked("sender"),
            recipient: Addr::unchecked("recipient"),
            amount: Uint128::new(1000),
            denom: "uakt".to_string(),
            expiration: 123,
            highest_claim: Uint128::zero(),
            status: ChannelStatus::Open,
        };
        let json = serde_json::to_string(&channel).unwrap();
        assert!(json.contains(r#""id":"""#));
    }

    #[test]
    fn test_uint128_max_serialization() {
        let channel = PaymentChannel {
            id: "max_test".to_string(),
            sender: Addr::unchecked("sender"),
            recipient: Addr::unchecked("recipient"),
            amount: Uint128::MAX,
            denom: "uakt".to_string(),
            expiration: u64::MAX,
            highest_claim: Uint128::MAX,
            status: ChannelStatus::Expired,
        };

        let json = serde_json::to_string(&channel).unwrap();
        let restored: PaymentChannel = serde_json::from_str(&json).unwrap();
        assert_eq!(channel, restored);
    }
}
