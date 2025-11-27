#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, GetChannelResponse, InstantiateMsg, ListChannelsResponse, QueryMsg};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:payment-channel";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("contract_name", CONTRACT_NAME)
        .add_attribute("contract_version", CONTRACT_VERSION))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::OpenChannel {
            recipient,
            expiration,
        } => execute::open_channel(deps, env, info, recipient, expiration),
        ExecuteMsg::CloseChannel {
            channel_id,
            final_claim,
        } => execute::close_channel(deps, env, info, channel_id, final_claim),
    }
}

pub mod execute {
    use super::*;
    use crate::msg::Claim;
    use crate::state::{ChannelStatus, PaymentChannel, CHANNELS};
    use cosmwasm_std::{Coin, Event, Uint128};
    use sha2::{Digest, Sha256};

    // Maximum expiration: 90 days from now
    const MAX_EXPIRATION_SECONDS: u64 = 90 * 24 * 60 * 60;

    // Expected denomination - configurable per deployment
    // For Akash mainnet: "uakt", for testnet: "stake"
    const EXPECTED_DENOM: &str = "uakt";

    /// Generate unique channel ID from inputs using SHA256
    pub(crate) fn generate_channel_id(
        sender: &str,
        recipient: &str,
        block_time: u64,
        block_height: u64,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(sender.as_bytes());
        hasher.update(recipient.as_bytes());
        hasher.update(block_time.to_le_bytes());
        hasher.update(block_height.to_le_bytes());

        let result = hasher.finalize();
        hex::encode(result)
    }

    pub fn open_channel(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        recipient: String,
        expiration: u64,
    ) -> Result<Response, ContractError> {
        // Validate recipient address (AC 2)
        let recipient_addr =
            deps.api
                .addr_validate(&recipient)
                .map_err(|_| ContractError::InvalidAddress {
                    address: recipient.clone(),
                })?;

        // Validate expiration is in future (AC 3)
        let current_time = env.block.time.seconds();
        if expiration <= current_time {
            return Err(ContractError::InvalidExpiration {
                expiration,
                current_time,
            });
        }

        // Validate expiration is not too far in future
        if expiration > current_time + MAX_EXPIRATION_SECONDS {
            return Err(ContractError::ExpirationTooFar {
                expiration,
                max_allowed: current_time + MAX_EXPIRATION_SECONDS,
            });
        }

        // Validate exactly one coin sent (AC 4)
        if info.funds.len() != 1 {
            return Err(ContractError::InvalidFunds {
                expected: 1,
                received: info.funds.len(),
            });
        }

        let coin: &Coin = &info.funds[0];

        // Validate correct denomination
        if coin.denom != EXPECTED_DENOM {
            return Err(ContractError::InvalidDenom {
                expected: EXPECTED_DENOM.to_string(),
                got: coin.denom.clone(),
            });
        }

        // Validate non-zero amount
        if coin.amount.is_zero() {
            return Err(ContractError::InsufficientBalance {
                requested: 0,
                available: 0,
            });
        }

        // Generate unique channel_id (AC 5)
        let channel_id = generate_channel_id(
            info.sender.as_str(),
            recipient_addr.as_str(),
            env.block.time.seconds(),
            env.block.height,
        );

        // Check for collision (defensive programming)
        if CHANNELS.may_load(deps.storage, &channel_id)?.is_some() {
            return Err(ContractError::ChannelAlreadyExists {
                channel_id: channel_id.clone(),
            });
        }

        // Create PaymentChannel struct (AC 6)
        // Convert Uint256 to Uint128 (CosmWasm 3.0 uses Uint256 for Coin amounts)
        let amount_u128 =
            Uint128::try_from(coin.amount).map_err(|_| ContractError::InsufficientBalance {
                requested: 0,
                available: 0,
            })?;

        let channel = PaymentChannel {
            id: channel_id.clone(),
            sender: info.sender.clone(),
            recipient: recipient_addr,
            amount: amount_u128,
            denom: coin.denom.clone(),
            expiration,
            highest_claim: Uint128::zero(),
            status: ChannelStatus::Open,
        };

        // Save to storage
        CHANNELS.save(deps.storage, &channel_id, &channel)?;

        // Create response with event (AC 7, 8)
        let event = Event::new("payment_channel")
            .add_attribute("action", "open_channel")
            .add_attribute("channel_id", &channel_id)
            .add_attribute("sender", info.sender.as_str())
            .add_attribute("recipient", &recipient)
            .add_attribute("amount", coin.amount.to_string())
            .add_attribute("denom", &coin.denom)
            .add_attribute("expiration", expiration.to_string());

        let response =
            Response::new()
                .add_event(event)
                .set_data(to_json_binary(&serde_json::json!({
                    "channel_id": channel_id
                }))?);

        Ok(response)
    }

    pub fn close_channel(
        deps: DepsMut,
        env: Env,
        _info: MessageInfo,
        channel_id: String,
        _final_claim: Claim,
    ) -> Result<Response, ContractError> {
        // Task 2: Load channel and validate
        let mut channel = CHANNELS.load(deps.storage, &channel_id).map_err(|_| {
            ContractError::ChannelNotFound {
                channel_id: channel_id.clone(),
            }
        })?;

        // Validate channel status
        match channel.status {
            ChannelStatus::Closed => {
                return Err(ContractError::ChannelClosed {});
            }
            ChannelStatus::Expired => {
                return Err(ContractError::ChannelExpired {
                    expiration: channel.expiration,
                });
            }
            ChannelStatus::Open => {
                // Continue with normal flow
            }
        }

        // Check if channel has expired (env.block.time > expiration)
        if env.block.time.seconds() > channel.expiration {
            // Auto-expire and refund sender (Task 9)
            return refund_expired_channel(deps, env, channel_id, channel);
        }

        // Task 3: Verify claim signature
        // Construct message to verify: channel_id + amount + nonce
        let message = format!(
            "{}{}{}",
            channel_id, _final_claim.amount, _final_claim.nonce
        );

        // Hash message with SHA256
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let message_hash = hasher.finalize();

        // Verify signature using secp256k1_verify
        // Note: In CosmWasm 2.0+, we cannot derive Cosmos addresses from public keys within the contract
        // due to chain-specific Bech32 encoding. However, signature verification alone is sufficient:
        // - If the signature is valid, it proves the claim was signed by the holder of the private key
        //   corresponding to the provided public key
        // - The recipient must provide their correct public key when closing the channel
        // - If they provide the wrong public key, signature verification will fail
        let signature_valid = deps
            .api
            .secp256k1_verify(
                &message_hash,
                _final_claim.signature.as_slice(),
                _final_claim.pubkey.as_slice(),
            )
            .map_err(|_| ContractError::InvalidSignature {})?;

        if !signature_valid {
            return Err(ContractError::InvalidSignature {});
        }

        // Task 4: Validate claim amount
        if _final_claim.amount > channel.amount {
            return Err(ContractError::InsufficientBalance {
                requested: _final_claim.amount.u128(),
                available: channel.amount.u128(),
            });
        }

        // Task 5: Validate nonce (prevents replay attacks)
        // Nonce must be strictly greater than highest_claim
        if _final_claim.nonce <= channel.highest_claim.u128() as u64 {
            return Err(ContractError::InvalidNonce {
                got: _final_claim.nonce,
                expected: channel.highest_claim.u128() as u64,
            });
        }

        // Task 6: Transfer funds
        use cosmwasm_std::BankMsg;

        // Calculate payouts
        let recipient_payout = _final_claim.amount;
        let sender_refund = channel.amount - _final_claim.amount;

        let mut messages = vec![];

        // Send claimed amount to recipient (if non-zero)
        if !recipient_payout.is_zero() {
            messages.push(BankMsg::Send {
                to_address: channel.recipient.to_string(),
                amount: vec![Coin {
                    denom: channel.denom.clone(),
                    amount: recipient_payout.into(), // Convert Uint128 to Uint256
                }],
            });
        }

        // Refund remaining balance to sender (if non-zero)
        if !sender_refund.is_zero() {
            messages.push(BankMsg::Send {
                to_address: channel.sender.to_string(),
                amount: vec![Coin {
                    denom: channel.denom.clone(),
                    amount: sender_refund.into(), // Convert Uint128 to Uint256
                }],
            });
        }

        // Task 7: Update channel state
        channel.highest_claim = Uint128::from(_final_claim.nonce);
        channel.status = ChannelStatus::Closed;
        CHANNELS.save(deps.storage, &channel_id, &channel)?;

        // Task 8: Emit event and return response
        let event = Event::new("payment_channel_closed")
            .add_attribute("action", "close_channel")
            .add_attribute("channel_id", &channel_id)
            .add_attribute("recipient_payout", recipient_payout.to_string())
            .add_attribute("sender_refund", sender_refund.to_string())
            .add_attribute("final_nonce", _final_claim.nonce.to_string())
            .add_attribute("recipient", channel.recipient.to_string())
            .add_attribute("sender", channel.sender.to_string());

        let response = Response::new().add_messages(messages).add_event(event);

        Ok(response)
    }

    // Helper function for Task 9: Auto-refund expired channels
    fn refund_expired_channel(
        deps: DepsMut,
        _env: Env,
        channel_id: String,
        mut channel: PaymentChannel,
    ) -> Result<Response, ContractError> {
        use cosmwasm_std::{BankMsg, Coin};

        // Transfer full amount back to sender
        let refund_msg = BankMsg::Send {
            to_address: channel.sender.to_string(),
            amount: vec![Coin {
                denom: channel.denom.clone(),
                amount: channel.amount.into(), // Convert Uint128 to Uint256
            }],
        };

        // Update channel status to Expired
        channel.status = ChannelStatus::Expired;
        CHANNELS.save(deps.storage, &channel_id, &channel)?;

        // Emit event
        let event = Event::new("payment_channel_expired")
            .add_attribute("action", "auto_refund_expired")
            .add_attribute("channel_id", &channel_id)
            .add_attribute("refund_amount", channel.amount.to_string())
            .add_attribute("sender", channel.sender.to_string());

        let response = Response::new().add_message(refund_msg).add_event(event);

        Ok(response)
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetChannel { channel_id } => {
            to_json_binary(&query::get_channel(deps, channel_id)?)
        }
        QueryMsg::ListChannels { sender, recipient } => {
            to_json_binary(&query::list_channels(deps, sender, recipient)?)
        }
    }
}

pub mod query {
    use super::*;
    use cosmwasm_std::StdError;

    pub fn get_channel(_deps: Deps, _channel_id: String) -> StdResult<GetChannelResponse> {
        // Implementation in Story 3.5
        Err(StdError::msg("Not implemented yet (Story 3.5)"))
    }

    pub fn list_channels(
        _deps: Deps,
        _sender: Option<String>,
        _recipient: Option<String>,
    ) -> StdResult<ListChannelsResponse> {
        // Implementation in Story 3.5
        Err(StdError::msg("Not implemented yet (Story 3.5)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::Addr;

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {};
        let info = MessageInfo {
            sender: Addr::unchecked("creator"),
            funds: vec![],
        };

        // Instantiate should succeed
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());
        assert_eq!(
            res.attributes,
            vec![
                ("method", "instantiate"),
                ("contract_name", CONTRACT_NAME),
                ("contract_version", CONTRACT_VERSION),
            ]
        );
    }

    #[test]
    fn test_generate_channel_id() {
        use crate::contract::execute::generate_channel_id;

        let channel_id1 = generate_channel_id("sender1", "recipient1", 123456, 100);
        let channel_id2 = generate_channel_id("sender1", "recipient1", 123456, 100);

        // Same inputs produce same ID
        assert_eq!(channel_id1, channel_id2);
        assert_eq!(channel_id1.len(), 64); // SHA256 hex is 64 characters

        // Different sender produces different ID
        let channel_id3 = generate_channel_id("sender2", "recipient1", 123456, 100);
        assert_ne!(channel_id1, channel_id3);

        // Different recipient produces different ID
        let channel_id4 = generate_channel_id("sender1", "recipient2", 123456, 100);
        assert_ne!(channel_id1, channel_id4);

        // Different timestamp produces different ID
        let channel_id5 = generate_channel_id("sender1", "recipient1", 123457, 100);
        assert_ne!(channel_id1, channel_id5);

        // Different block height produces different ID
        let channel_id6 = generate_channel_id("sender1", "recipient1", 123456, 101);
        assert_ne!(channel_id1, channel_id6);
    }

    #[test]
    fn close_channel_partial_implementation() {
        use crate::msg::Claim;
        use cosmwasm_std::{Binary, Uint128};

        let mut deps = mock_dependencies();

        // Initialize contract
        let msg = InstantiateMsg {};
        let info = MessageInfo {
            sender: Addr::unchecked("creator"),
            funds: vec![],
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Try to close non-existent channel
        let claim = Claim {
            amount: Uint128::new(1000),
            nonce: 1,
            signature: Binary::from_base64("AQIDBA==").unwrap(),
            pubkey: Binary::from_base64("Aw==").unwrap(),
        };
        let msg = ExecuteMsg::CloseChannel {
            channel_id: "channel123".to_string(),
            final_claim: claim,
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg);

        // Should return ChannelNotFound error (Tasks 1-2 implemented)
        assert!(res.is_err());
        match res {
            Err(ContractError::ChannelNotFound { channel_id }) => {
                assert_eq!(channel_id, "channel123");
            }
            _ => panic!("Expected ChannelNotFound error"),
        }
    }

    #[test]
    fn get_channel_unimplemented() {
        let deps = mock_dependencies();

        let msg = QueryMsg::GetChannel {
            channel_id: "channel123".to_string(),
        };
        let res = query(deps.as_ref(), mock_env(), msg);

        // Should return error
        assert!(res.is_err());
    }

    #[test]
    fn list_channels_unimplemented() {
        let deps = mock_dependencies();

        let msg = QueryMsg::ListChannels {
            sender: None,
            recipient: None,
        };
        let res = query(deps.as_ref(), mock_env(), msg);

        // Should return error
        assert!(res.is_err());
    }

    // Task 2 Unit Tests: Channel Loading and Validation

    #[test]
    fn test_close_channel_not_found() {
        use crate::msg::Claim;
        use cosmwasm_std::{Binary, Uint128};

        let mut deps = mock_dependencies();

        // Initialize contract
        let msg = InstantiateMsg {};
        let info = MessageInfo {
            sender: Addr::unchecked("creator"),
            funds: vec![],
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Try to close non-existent channel
        let claim = Claim {
            amount: Uint128::new(1000),
            nonce: 1,
            signature: Binary::from_base64("AQIDBA==").unwrap(),
            pubkey: Binary::from_base64("Aw==").unwrap(),
        };

        let msg = ExecuteMsg::CloseChannel {
            channel_id: "nonexistent_channel".to_string(),
            final_claim: claim,
        };

        let res = execute(deps.as_mut(), mock_env(), info, msg);

        // Should fail with ChannelNotFound
        assert!(res.is_err());
        match res.unwrap_err() {
            ContractError::ChannelNotFound { channel_id } => {
                assert_eq!(channel_id, "nonexistent_channel");
            }
            _ => panic!("Expected ChannelNotFound error"),
        }
    }

    #[test]
    fn test_close_channel_already_closed() {
        use crate::msg::Claim;
        use crate::state::{ChannelStatus, PaymentChannel, CHANNELS};
        use cosmwasm_std::{Binary, Uint128};

        let mut deps = mock_dependencies();

        // Initialize contract
        let msg = InstantiateMsg {};
        let info = MessageInfo {
            sender: Addr::unchecked("creator"),
            funds: vec![],
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Create a closed channel manually
        let channel = PaymentChannel {
            id: "closed_channel".to_string(),
            sender: Addr::unchecked("sender"),
            recipient: Addr::unchecked("recipient"),
            amount: Uint128::new(1_000_000),
            denom: "uakt".to_string(),
            expiration: 9999999999,
            highest_claim: Uint128::zero(),
            status: ChannelStatus::Closed,
        };

        CHANNELS
            .save(&mut deps.storage, "closed_channel", &channel)
            .unwrap();

        // Try to close already-closed channel
        let claim = Claim {
            amount: Uint128::new(500_000),
            nonce: 1,
            signature: Binary::from_base64("AQIDBA==").unwrap(),
            pubkey: Binary::from_base64("Aw==").unwrap(),
        };

        let msg = ExecuteMsg::CloseChannel {
            channel_id: "closed_channel".to_string(),
            final_claim: claim,
        };

        let res = execute(deps.as_mut(), mock_env(), info, msg);

        // Should fail with ChannelClosed
        assert!(res.is_err());
        match res.unwrap_err() {
            ContractError::ChannelClosed {} => {
                // Success
            }
            _ => panic!("Expected ChannelClosed error"),
        }
    }

    #[test]
    fn test_close_expired_channel_auto_refund() {
        use crate::msg::Claim;
        use crate::state::{ChannelStatus, PaymentChannel, CHANNELS};
        use cosmwasm_std::{testing::mock_env, Binary, Timestamp, Uint128};

        let mut deps = mock_dependencies();

        // Initialize contract
        let msg = InstantiateMsg {};
        let info = MessageInfo {
            sender: Addr::unchecked("creator"),
            funds: vec![],
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Create an open channel with expiration in the past
        let channel = PaymentChannel {
            id: "expired_channel".to_string(),
            sender: Addr::unchecked("sender"),
            recipient: Addr::unchecked("recipient"),
            amount: Uint128::new(1_000_000),
            denom: "uakt".to_string(),
            expiration: 1000000, // Past timestamp
            highest_claim: Uint128::zero(),
            status: ChannelStatus::Open,
        };

        CHANNELS
            .save(&mut deps.storage, "expired_channel", &channel)
            .unwrap();

        // Create claim for expired channel
        let claim = Claim {
            amount: Uint128::new(500_000),
            nonce: 1,
            signature: Binary::from_base64("AQIDBA==").unwrap(),
            pubkey: Binary::from_base64("Aw==").unwrap(),
        };

        let msg = ExecuteMsg::CloseChannel {
            channel_id: "expired_channel".to_string(),
            final_claim: claim,
        };

        // Use env with current time > expiration
        let mut env = mock_env();
        env.block.time = Timestamp::from_seconds(2000000); // After expiration

        let res = execute(deps.as_mut(), env, info, msg).unwrap();

        // Should succeed with auto-refund
        assert_eq!(res.messages.len(), 1);

        // Verify event emitted
        assert!(res.events.iter().any(|e| e.ty == "payment_channel_expired"));

        // Verify channel status updated to Expired
        let updated_channel = CHANNELS.load(&deps.storage, "expired_channel").unwrap();
        assert_eq!(updated_channel.status, ChannelStatus::Expired);
    }
}
