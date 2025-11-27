use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Binary, Uint128};

use crate::state::{ChannelStatus, PaymentChannel};

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    OpenChannel {
        recipient: String,
        expiration: u64,
    },
    CloseChannel {
        channel_id: String,
        final_claim: Claim,
    },
}

#[cw_serde]
pub struct Claim {
    pub amount: Uint128,
    pub nonce: u64,
    pub signature: Binary,
    pub pubkey: Binary, // Recipient's public key (33 bytes compressed secp256k1)
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(GetChannelResponse)]
    GetChannel { channel_id: String },
    #[returns(ListChannelsResponse)]
    ListChannels {
        sender: Option<String>,
        recipient: Option<String>,
        status: Option<ChannelStatus>,
        limit: Option<u32>,
        start_after: Option<String>,
    },
}

// Query response types
#[cw_serde]
pub struct GetChannelResponse {
    pub channel: PaymentChannel,
}

#[cw_serde]
pub struct ListChannelsResponse {
    pub channels: Vec<PaymentChannel>,
    pub total: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_msg_open_channel_json() {
        let msg = ExecuteMsg::OpenChannel {
            recipient: "cosmos1...".to_string(),
            expiration: 99999,
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("open_channel"));
        assert!(json.contains("recipient"));
        assert!(json.contains("cosmos1..."));
    }

    #[test]
    fn test_execute_msg_open_channel_serialization() {
        let msg = ExecuteMsg::OpenChannel {
            recipient: "cosmos1abc".to_string(),
            expiration: 12345,
        };

        let json = serde_json::to_string(&msg).unwrap();
        let restored: ExecuteMsg = serde_json::from_str(&json).unwrap();

        assert_eq!(msg, restored);
    }

    #[test]
    fn test_execute_msg_close_channel_serialization() {
        let claim = Claim {
            amount: Uint128::new(500000),
            nonce: 42,
            signature: Binary::from_base64("AQIDBA==").unwrap(),
            pubkey: Binary::from_base64("Aw==").unwrap(), // 33-byte compressed pubkey placeholder
        };

        let msg = ExecuteMsg::CloseChannel {
            channel_id: "channel123".to_string(),
            final_claim: claim.clone(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("close_channel"));
        assert!(json.contains("channel_id"));

        let restored: ExecuteMsg = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn test_claim_serialization() {
        let claim = Claim {
            amount: Uint128::new(500000),
            nonce: 42,
            signature: Binary::from_base64("AQIDBA==").unwrap(),
            pubkey: Binary::from_base64("Aw==").unwrap(), // 33-byte compressed pubkey placeholder
        };

        let json = serde_json::to_string(&claim).unwrap();
        let restored: Claim = serde_json::from_str(&json).unwrap();

        assert_eq!(claim, restored);
    }

    #[test]
    fn test_claim_uint128_max() {
        let claim = Claim {
            amount: Uint128::MAX,
            nonce: u64::MAX,
            signature: Binary::from_base64("AQIDBA==").unwrap(),
            pubkey: Binary::from_base64("Aw==").unwrap(), // 33-byte compressed pubkey placeholder
        };

        let json = serde_json::to_string(&claim).unwrap();
        let restored: Claim = serde_json::from_str(&json).unwrap();

        assert_eq!(claim, restored);
    }

    #[test]
    fn test_query_msg_get_channel_serialization() {
        let msg = QueryMsg::GetChannel {
            channel_id: "channel456".to_string(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("get_channel"));
        assert!(json.contains("channel_id"));

        let restored: QueryMsg = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn test_query_msg_list_channels_serialization() {
        let msg = QueryMsg::ListChannels {
            sender: Some("cosmos1sender".to_string()),
            recipient: None,
            status: None,
            limit: None,
            start_after: None,
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("list_channels"));

        let restored: QueryMsg = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn test_query_msg_list_channels_both_filters() {
        let msg = QueryMsg::ListChannels {
            sender: Some("cosmos1sender".to_string()),
            recipient: Some("cosmos1recipient".to_string()),
            status: None,
            limit: None,
            start_after: None,
        };

        let json = serde_json::to_string(&msg).unwrap();
        let restored: QueryMsg = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn test_instantiate_msg() {
        let msg = InstantiateMsg {};
        let json = serde_json::to_string(&msg).unwrap();
        let restored: InstantiateMsg = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn test_get_channel_response_serialization() {
        use crate::state::ChannelStatus;
        use cosmwasm_std::Addr;

        let channel = PaymentChannel {
            id: "test123".to_string(),
            sender: Addr::unchecked("cosmos1sender"),
            recipient: Addr::unchecked("cosmos1recipient"),
            amount: Uint128::new(1000000),
            denom: "uakt".to_string(),
            expiration: 1234567890,
            highest_claim: Uint128::zero(),
            status: ChannelStatus::Open,
        };

        let response = GetChannelResponse { channel };

        let json = serde_json::to_string(&response).unwrap();
        let restored: GetChannelResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(response, restored);
    }

    #[test]
    fn test_list_channels_response_serialization() {
        use crate::state::ChannelStatus;
        use cosmwasm_std::Addr;

        let channel1 = PaymentChannel {
            id: "test1".to_string(),
            sender: Addr::unchecked("cosmos1sender"),
            recipient: Addr::unchecked("cosmos1recipient"),
            amount: Uint128::new(1000000),
            denom: "uakt".to_string(),
            expiration: 1234567890,
            highest_claim: Uint128::zero(),
            status: ChannelStatus::Open,
        };

        let channel2 = PaymentChannel {
            id: "test2".to_string(),
            sender: Addr::unchecked("cosmos1sender2"),
            recipient: Addr::unchecked("cosmos1recipient2"),
            amount: Uint128::new(2000000),
            denom: "stake".to_string(),
            expiration: 9999999999,
            highest_claim: Uint128::new(500000),
            status: ChannelStatus::Closed,
        };

        let response = ListChannelsResponse {
            channels: vec![channel1, channel2],
            total: 2,
        };

        let json = serde_json::to_string(&response).unwrap();
        let restored: ListChannelsResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(response, restored);
        assert_eq!(restored.total, 2);
        assert_eq!(restored.channels.len(), 2);
    }

    #[test]
    fn test_query_msg_list_channels_with_all_filters() {
        let msg = QueryMsg::ListChannels {
            sender: Some("cosmos1sender".to_string()),
            recipient: Some("cosmos1recipient".to_string()),
            status: Some(ChannelStatus::Open),
            limit: Some(10),
            start_after: Some("channel_abc".to_string()),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let restored: QueryMsg = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn test_query_msg_list_channels_empty_filters() {
        let msg = QueryMsg::ListChannels {
            sender: None,
            recipient: None,
            status: None,
            limit: None,
            start_after: None,
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("list_channels"));

        let restored: QueryMsg = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, restored);
    }
}
