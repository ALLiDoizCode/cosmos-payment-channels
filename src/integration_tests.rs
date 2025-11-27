#[cfg(test)]
mod tests {
    use crate::helpers::PaymentChannelContract;
    use crate::msg::{Claim, ExecuteMsg, InstantiateMsg, QueryMsg};
    use crate::state::{ChannelStatus, PaymentChannel};
    use cosmwasm_std::{Addr, Binary, Empty, Uint128};
    use cw_multi_test::{App, AppBuilder, Contract, ContractWrapper, Executor};

    pub fn contract_template() -> Box<dyn Contract<Empty>> {
        let contract = ContractWrapper::new(
            crate::contract::execute,
            crate::contract::instantiate,
            crate::contract::query,
        );
        Box::new(contract)
    }

    const ADMIN: &str = "ADMIN";

    fn mock_app() -> App {
        use cosmwasm_std::coins;

        let mut app = AppBuilder::new().build(|_router, _api, _storage| {});

        // Initialize balances for test account using addr_make
        let sender = app.api().addr_make("sender");
        app.init_modules(|router, _api, storage| {
            router
                .bank
                .init_balance(storage, &sender, coins(10_000_000_000, "uakt"))
                .unwrap();
        });

        app
    }

    fn proper_instantiate() -> (App, PaymentChannelContract) {
        let mut app = mock_app();
        let code_id = app.store_code(contract_template());

        let msg = InstantiateMsg {};
        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked(ADMIN),
                &msg,
                &[],
                "payment-channel",
                None,
            )
            .unwrap();

        let contract = PaymentChannelContract(contract_addr);

        (app, contract)
    }

    #[test]
    fn test_proper_instantiate() {
        let (_app, _contract) = proper_instantiate();
        // Instantiation should succeed
    }

    #[test]
    fn test_payment_channel_serialization() {
        // Verify PaymentChannel round-trip serialization
        let channel = PaymentChannel {
            id: "test_channel_123".to_string(),
            sender: Addr::unchecked("cosmos1sender"),
            recipient: Addr::unchecked("cosmos1recipient"),
            amount: Uint128::new(1000000),
            denom: "uakt".to_string(),
            expiration: 9999999,
            highest_claim: Uint128::zero(),
            status: ChannelStatus::Open,
        };

        let json = serde_json::to_string(&channel).unwrap();
        let restored: PaymentChannel = serde_json::from_str(&json).unwrap();

        assert_eq!(channel.id, restored.id);
        assert_eq!(channel.sender, restored.sender);
        assert_eq!(channel.amount, restored.amount);
    }

    #[test]
    fn test_execute_msg_serialization() {
        // Verify OpenChannel JSON serialization
        let open_msg = ExecuteMsg::OpenChannel {
            recipient: "cosmos1recipient".to_string(),
            expiration: 12345,
        };

        let json = serde_json::to_string(&open_msg).unwrap();
        assert!(json.contains("open_channel"));
        assert!(json.contains("recipient"));

        let restored: ExecuteMsg = serde_json::from_str(&json).unwrap();
        match restored {
            ExecuteMsg::OpenChannel {
                recipient,
                expiration,
            } => {
                assert_eq!(recipient, "cosmos1recipient");
                assert_eq!(expiration, 12345);
            }
            _ => panic!("Expected OpenChannel variant"),
        }

        // Verify CloseChannel JSON serialization
        let claim = Claim {
            amount: Uint128::new(500),
            nonce: 1,
            signature: Binary::from_base64("AQIDBA==").unwrap(),
            pubkey: Binary::from_base64("Aw==").unwrap(),
        };

        let close_msg = ExecuteMsg::CloseChannel {
            channel_id: "channel123".to_string(),
            final_claim: claim.clone(),
        };

        let json = serde_json::to_string(&close_msg).unwrap();
        assert!(json.contains("close_channel"));

        let _restored: ExecuteMsg = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn test_query_msg_serialization() {
        // Verify GetChannel JSON
        let get_msg = QueryMsg::GetChannel {
            channel_id: "channel456".to_string(),
        };

        let json = serde_json::to_string(&get_msg).unwrap();
        assert!(json.contains("get_channel"));

        let restored: QueryMsg = serde_json::from_str(&json).unwrap();
        match restored {
            QueryMsg::GetChannel { channel_id } => {
                assert_eq!(channel_id, "channel456");
            }
            _ => panic!("Expected GetChannel variant"),
        }

        // Verify ListChannels JSON
        let list_msg = QueryMsg::ListChannels {
            sender: Some("cosmos1sender".to_string()),
            recipient: None,
            status: None,
            limit: None,
            start_after: None,
        };

        let json = serde_json::to_string(&list_msg).unwrap();
        assert!(json.contains("list_channels"));

        let _restored: QueryMsg = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn test_claim_serialization() {
        let claim = Claim {
            amount: Uint128::new(999999),
            nonce: 42,
            signature: Binary::from_base64("AQIDBA==").unwrap(),
            pubkey: Binary::from_base64("Aw==").unwrap(),
        };

        let json = serde_json::to_string(&claim).unwrap();
        assert!(json.contains("amount"));
        assert!(json.contains("nonce"));
        assert!(json.contains("signature"));

        let restored: Claim = serde_json::from_str(&json).unwrap();
        assert_eq!(claim.amount, restored.amount);
        assert_eq!(claim.nonce, restored.nonce);
    }

    #[test]
    fn test_schema_validation() {
        use std::fs;

        // Verify schema files exist and are valid JSON
        let schema_files = vec![
            "schema/payment-channel.json",
            "schema/raw/execute.json",
            "schema/raw/query.json",
            "schema/raw/response_to_get_channel.json",
            "schema/raw/response_to_list_channels.json",
        ];

        for file_path in schema_files {
            let full_path = format!(
                "/Users/jonathangreen/Documents/cosmos-payment-channels/{}",
                file_path
            );
            assert!(
                fs::metadata(&full_path).is_ok(),
                "Schema file should exist: {}",
                file_path
            );

            let content = fs::read_to_string(&full_path)
                .unwrap_or_else(|_| panic!("Should be able to read {}", file_path));

            let _parsed: serde_json::Value = serde_json::from_str(&content)
                .unwrap_or_else(|_| panic!("Schema should be valid JSON: {}", file_path));
        }
    }

    #[test]
    fn test_invalid_json_deserialization() {
        // Verify errors on malformed input
        let invalid_json = r#"{"id": 123, "sender": null}"#; // Wrong types
        let result: Result<PaymentChannel, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err(), "Should fail to deserialize invalid JSON");

        // Invalid ExecuteMsg
        let invalid_msg = r#"{"unknown_variant": {}}"#;
        let result: Result<ExecuteMsg, _> = serde_json::from_str(invalid_msg);
        assert!(result.is_err(), "Should fail on unknown variant");
    }

    #[test]
    fn test_uint128_boundary_conditions() {
        // Verify Uint128::MAX serialization
        let claim = Claim {
            amount: Uint128::MAX,
            nonce: u64::MAX,
            signature: Binary::from_base64("AQID").unwrap(),
            pubkey: Binary::from_base64("Aw==").unwrap(),
        };

        let json = serde_json::to_string(&claim).unwrap();
        let restored: Claim = serde_json::from_str(&json).unwrap();
        assert_eq!(claim.amount, restored.amount);
        assert_eq!(claim.nonce, restored.nonce);

        // Verify PaymentChannel with max values
        let channel = PaymentChannel {
            id: "max_channel".to_string(),
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
        assert_eq!(channel.amount, restored.amount);
        assert_eq!(channel.expiration, restored.expiration);
    }

    // OpenChannel Integration Tests (Story 3.3)

    #[test]
    fn test_open_channel_success() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();

        // Use a valid test address - in cw-multi-test, we can create one
        let recipient = app.api().addr_make("recipient");

        // Create OpenChannel message with valid expiration (30 days from now)
        let block_time = app.block_info().time.seconds();
        let expiration = block_time + (30 * 24 * 60 * 60); // 30 days

        let msg = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration,
        };

        let funds = vec![Coin::new(1_000_000u128, "uakt")];

        let sender = app.api().addr_make("sender");

        // Execute OpenChannel
        let res = app
            .execute_contract(sender, contract.addr(), &msg, &funds)
            .unwrap();

        // Verify response has data
        assert!(res.data.is_some());

        // Parse channel_id from response
        let data: serde_json::Value = serde_json::from_slice(&res.data.unwrap()).unwrap();
        let channel_id = data["channel_id"].as_str().unwrap();
        assert_eq!(channel_id.len(), 64); // SHA256 hex is 64 characters

        // Verify event was emitted
        let event = res.events.iter().find(|e| e.ty == "wasm-payment_channel");
        assert!(event.is_some());

        let event = event.unwrap();
        assert!(event
            .attributes
            .iter()
            .any(|a| a.key == "action" && a.value == "open_channel"));
        assert!(event
            .attributes
            .iter()
            .any(|a| a.key == "channel_id" && a.value == channel_id));
    }

    #[test]
    fn test_open_channel_invalid_recipient() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();

        let block_time = app.block_info().time.seconds();

        let msg = ExecuteMsg::OpenChannel {
            recipient: "invalid_address".to_string(),
            expiration: block_time + (30 * 24 * 60 * 60),
        };

        let funds = vec![Coin::new(1_000_000u128, "uakt")];

        let sender = app.api().addr_make("sender");

        let err = app
            .execute_contract(sender, contract.addr(), &msg, &funds)
            .unwrap_err();

        assert!(err.to_string().contains("Invalid address"));
    }

    #[test]
    fn test_open_channel_empty_recipient() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();

        let block_time = app.block_info().time.seconds();

        let msg = ExecuteMsg::OpenChannel {
            recipient: "".to_string(),
            expiration: block_time + (30 * 24 * 60 * 60),
        };

        let funds = vec![Coin::new(1_000_000u128, "uakt")];

        let sender = app.api().addr_make("sender");

        let err = app
            .execute_contract(sender, contract.addr(), &msg, &funds)
            .unwrap_err();

        assert!(err.to_string().contains("Invalid address"));
    }

    #[test]
    fn test_open_channel_past_expiration() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();
        let recipient = app.api().addr_make("recipient");
        let sender = app.api().addr_make("sender");

        let msg = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration: 1, // Past timestamp
        };

        let funds = vec![Coin::new(1_000_000u128, "uakt")];

        let err = app
            .execute_contract(sender, contract.addr(), &msg, &funds)
            .unwrap_err();

        assert!(err.to_string().contains("Invalid expiration"));
    }

    #[test]
    fn test_open_channel_current_expiration() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();
        let recipient = app.api().addr_make("recipient");
        let sender = app.api().addr_make("sender");

        // Get current block time
        let block_time = app.block_info().time.seconds();

        let msg = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration: block_time, // Current timestamp
        };

        let funds = vec![Coin::new(1_000_000u128, "uakt")];

        let err = app
            .execute_contract(sender, contract.addr(), &msg, &funds)
            .unwrap_err();

        assert!(err.to_string().contains("Invalid expiration"));
    }

    #[test]
    fn test_open_channel_expiration_too_far() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();
        let recipient = app.api().addr_make("recipient");
        let sender = app.api().addr_make("sender");

        let block_time = app.block_info().time.seconds();

        let msg = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration: block_time + (365 * 24 * 60 * 60), // 1 year (> 90 days)
        };

        let funds = vec![Coin::new(1_000_000u128, "uakt")];

        let err = app
            .execute_contract(sender, contract.addr(), &msg, &funds)
            .unwrap_err();

        assert!(err.to_string().contains("Expiration too far"));
    }

    #[test]
    fn test_open_channel_no_funds() {
        let (mut app, contract) = proper_instantiate();
        let recipient = app.api().addr_make("recipient");
        let sender = app.api().addr_make("sender");
        let block_time = app.block_info().time.seconds();

        let msg = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration: block_time + (30 * 24 * 60 * 60),
        };

        let funds = vec![]; // No funds attached

        let err = app
            .execute_contract(sender, contract.addr(), &msg, &funds)
            .unwrap_err();

        // Check for funds validation error
        let err_str = err.to_string();
        assert!(err_str.contains("Invalid funds") || err_str.contains("expected 1"));
    }

    #[test]
    fn test_open_channel_multiple_coins() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();
        let recipient = app.api().addr_make("recipient");
        let sender = app.api().addr_make("sender");
        let block_time = app.block_info().time.seconds();

        let msg = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration: block_time + (30 * 24 * 60 * 60),
        };

        let funds = vec![
            Coin::new(1_000_000u128, "uakt"),
            Coin::new(500_000u128, "uatom"),
        ];

        let _err = app
            .execute_contract(sender, contract.addr(), &msg, &funds)
            .unwrap_err();

        // Test passes if it gets an error (unwrap_err succeeds)
        // The exact error message may vary between testing and production
    }

    #[test]
    fn test_open_channel_wrong_denom() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();
        let recipient = app.api().addr_make("recipient");
        let sender = app.api().addr_make("sender");
        let block_time = app.block_info().time.seconds();

        let msg = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration: block_time + (30 * 24 * 60 * 60),
        };

        // Initialize sender with wrong denom balance
        use cosmwasm_std::coins;
        app.init_modules(|router, _api, storage| {
            router
                .bank
                .init_balance(storage, &sender, coins(10_000_000, "uatom"))
                .unwrap();
        });

        let funds = vec![Coin::new(1_000_000u128, "uatom")]; // Wrong denom

        let err = app
            .execute_contract(sender, contract.addr(), &msg, &funds)
            .unwrap_err();

        let err_str = err.to_string();
        assert!(err_str.contains("Invalid denomination") || err_str.contains("expected"));
    }

    #[test]
    fn test_open_channel_zero_amount() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();
        let recipient = app.api().addr_make("recipient");
        let sender = app.api().addr_make("sender");
        let block_time = app.block_info().time.seconds();

        let msg = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration: block_time + (30 * 24 * 60 * 60),
        };

        let funds = vec![Coin::new(0u128, "uakt")];

        let err = app
            .execute_contract(sender, contract.addr(), &msg, &funds)
            .unwrap_err();

        // cw-multi-test returns error about zero coins in funds
        let err_str = err.to_string();
        assert!(
            err_str.contains("Insufficient")
                || err_str.contains("zero")
                || err_str.contains("empty")
        );
    }

    #[test]
    fn test_open_channel_channel_id_uniqueness() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();
        let recipient = app.api().addr_make("recipient");
        let sender = app.api().addr_make("sender");
        let block_time = app.block_info().time.seconds();

        // Open first channel
        let msg1 = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration: block_time + (30 * 24 * 60 * 60),
        };

        let funds1 = vec![Coin::new(1_000_000u128, "uakt")];

        let res1 = app
            .execute_contract(sender.clone(), contract.addr(), &msg1, &funds1)
            .unwrap();

        let data1: serde_json::Value = serde_json::from_slice(&res1.data.unwrap()).unwrap();
        let channel_id1 = data1["channel_id"].as_str().unwrap();

        // Advance block to ensure different timestamp
        app.update_block(|block| {
            block.height += 1;
            block.time = block.time.plus_seconds(10);
        });

        // Open second channel with same sender/recipient
        let block_time2 = app.block_info().time.seconds();
        let msg2 = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration: block_time2 + (30 * 24 * 60 * 60),
        };

        let funds2 = vec![Coin::new(2_000_000u128, "uakt")];

        let res2 = app
            .execute_contract(sender, contract.addr(), &msg2, &funds2)
            .unwrap();

        let data2: serde_json::Value = serde_json::from_slice(&res2.data.unwrap()).unwrap();
        let channel_id2 = data2["channel_id"].as_str().unwrap();

        // Channel IDs should be different due to different timestamp/height
        assert_ne!(channel_id1, channel_id2);
    }

    #[test]
    fn test_open_channel_minimum_amount() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();
        let recipient = app.api().addr_make("recipient");
        let sender = app.api().addr_make("sender");
        let block_time = app.block_info().time.seconds();

        let msg = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration: block_time + (30 * 24 * 60 * 60),
        };

        let funds = vec![Coin::new(1u128, "uakt")]; // Minimum amount

        let res = app
            .execute_contract(sender, contract.addr(), &msg, &funds)
            .unwrap();

        assert!(res.data.is_some());
    }

    #[test]
    fn test_open_channel_minimum_expiration() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();
        let recipient = app.api().addr_make("recipient");
        let sender = app.api().addr_make("sender");

        let block_time = app.block_info().time.seconds();

        let msg = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration: block_time + 1, // 1 second in future (edge case)
        };

        let funds = vec![Coin::new(1_000_000u128, "uakt")];

        let res = app
            .execute_contract(sender, contract.addr(), &msg, &funds)
            .unwrap();

        assert!(res.data.is_some());
    }

    #[test]
    fn test_open_channel_maximum_expiration() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();
        let recipient = app.api().addr_make("recipient");
        let sender = app.api().addr_make("sender");

        let block_time = app.block_info().time.seconds();
        let max_exp = block_time + (90 * 24 * 60 * 60); // Exactly 90 days

        let msg = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration: max_exp,
        };

        let funds = vec![Coin::new(1_000_000u128, "uakt")];

        let res = app
            .execute_contract(sender, contract.addr(), &msg, &funds)
            .unwrap();

        assert!(res.data.is_some());
    }

    // Story 3.4: CloseChannel Integration Tests

    /// Helper function to generate a valid claim signature for testing
    /// Uses k256 to sign (channel_id + amount + nonce) with a test private key
    fn generate_test_claim(
        channel_id: &str,
        amount: u128,
        nonce: u64,
        private_key_bytes: &[u8; 32],
    ) -> Claim {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        use k256::ecdsa::{SigningKey, VerifyingKey};
        use sha2::{Digest, Sha256};

        // Create signing key from private key bytes
        let signing_key =
            SigningKey::from_bytes(private_key_bytes.into()).expect("Failed to create signing key");

        // Construct message: channel_id + amount + nonce
        // Use Uint128 formatting to match contract behavior
        let message = format!("{}{}{}", channel_id, Uint128::new(amount), nonce);

        // Hash message with SHA256
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let message_hash = hasher.finalize();

        // Sign the prehashed message
        let (signature, _recovery_id) = signing_key
            .sign_prehash_recoverable(&message_hash)
            .expect("Failed to sign");

        // Get public key (compressed, 33 bytes)
        let verifying_key = VerifyingKey::from(&signing_key);
        let pubkey_bytes = verifying_key.to_encoded_point(true); // true = compressed

        Claim {
            amount: Uint128::new(amount),
            nonce,
            signature: Binary::from(signature.to_bytes().as_slice()),
            pubkey: Binary::from(pubkey_bytes.as_bytes()),
        }
    }

    /// Test constant: Private key for generating test signatures
    /// WARNING: This is a TEST-ONLY key, never use in production!
    const TEST_PRIVATE_KEY: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    #[test]
    fn test_close_channel_success() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();
        let sender = app.api().addr_make("sender");
        let recipient = app.api().addr_make("recipient");

        // Open channel
        let block_time = app.block_info().time.seconds();
        let open_msg = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration: block_time + 86400, // 1 day
        };

        let funds = vec![Coin::new(1_000_000u128, "uakt")];
        let res = app
            .execute_contract(sender.clone(), contract.addr(), &open_msg, &funds)
            .unwrap();

        // Extract channel_id from response
        let data: serde_json::Value = serde_json::from_slice(&res.data.unwrap()).unwrap();
        let channel_id = data["channel_id"].as_str().unwrap().to_string();

        // Generate claim (600k out of 1M)
        let claim = generate_test_claim(&channel_id, 600_000, 1, &TEST_PRIVATE_KEY);

        // Close channel
        let close_msg = ExecuteMsg::CloseChannel {
            channel_id: channel_id.clone(),
            final_claim: claim,
        };

        let res = app
            .execute_contract(recipient.clone(), contract.addr(), &close_msg, &[])
            .unwrap();

        // Verify event emitted
        assert!(res
            .events
            .iter()
            .any(|e| e.ty == "wasm-payment_channel_closed"));

        // Success - channel closed with partial claim
    }

    #[test]
    fn test_close_channel_full_claim() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();
        let sender = app.api().addr_make("sender");
        let recipient = app.api().addr_make("recipient");

        // Open channel
        let block_time = app.block_info().time.seconds();
        let open_msg = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration: block_time + 86400,
        };

        let funds = vec![Coin::new(1_000_000u128, "uakt")];
        let res = app
            .execute_contract(sender.clone(), contract.addr(), &open_msg, &funds)
            .unwrap();

        let data: serde_json::Value = serde_json::from_slice(&res.data.unwrap()).unwrap();
        let channel_id = data["channel_id"].as_str().unwrap().to_string();

        // Claim full amount
        let claim = generate_test_claim(&channel_id, 1_000_000, 1, &TEST_PRIVATE_KEY);

        let close_msg = ExecuteMsg::CloseChannel {
            channel_id,
            final_claim: claim,
        };

        let res = app
            .execute_contract(recipient, contract.addr(), &close_msg, &[])
            .unwrap();

        // Verify success (full claim)
        assert!(res
            .events
            .iter()
            .any(|e| e.ty == "wasm-payment_channel_closed"));
    }

    #[test]
    fn test_close_channel_zero_claim() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();
        let sender = app.api().addr_make("sender");
        let recipient = app.api().addr_make("recipient");

        // Open channel
        let block_time = app.block_info().time.seconds();
        let open_msg = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration: block_time + 86400,
        };

        let funds = vec![Coin::new(1_000_000u128, "uakt")];
        let res = app
            .execute_contract(sender.clone(), contract.addr(), &open_msg, &funds)
            .unwrap();

        let data: serde_json::Value = serde_json::from_slice(&res.data.unwrap()).unwrap();
        let channel_id = data["channel_id"].as_str().unwrap().to_string();

        // Claim zero (full refund to sender)
        let claim = generate_test_claim(&channel_id, 0, 1, &TEST_PRIVATE_KEY);

        let close_msg = ExecuteMsg::CloseChannel {
            channel_id,
            final_claim: claim,
        };

        let res = app
            .execute_contract(recipient, contract.addr(), &close_msg, &[])
            .unwrap();

        // Verify success (zero claim - full refund)
        assert!(res
            .events
            .iter()
            .any(|e| e.ty == "wasm-payment_channel_closed"));
    }

    #[test]
    fn test_close_channel_invalid_signature() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();
        let sender = app.api().addr_make("sender");
        let recipient = app.api().addr_make("recipient");

        // Open channel
        let block_time = app.block_info().time.seconds();
        let open_msg = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration: block_time + 86400,
        };

        let funds = vec![Coin::new(1_000_000u128, "uakt")];
        let res = app
            .execute_contract(sender.clone(), contract.addr(), &open_msg, &funds)
            .unwrap();

        let data: serde_json::Value = serde_json::from_slice(&res.data.unwrap()).unwrap();
        let channel_id = data["channel_id"].as_str().unwrap().to_string();

        // Create claim with forged signature
        let mut claim = generate_test_claim(&channel_id, 500_000, 1, &TEST_PRIVATE_KEY);

        // Tamper with signature (flip first byte)
        let mut sig_bytes = claim.signature.to_vec();
        sig_bytes[0] ^= 0xFF;
        claim.signature = Binary::from(sig_bytes);

        let close_msg = ExecuteMsg::CloseChannel {
            channel_id,
            final_claim: claim,
        };

        let err = app
            .execute_contract(recipient, contract.addr(), &close_msg, &[])
            .unwrap_err();

        // Should fail with InvalidSignature
        assert!(err.to_string().contains("Invalid signature"));
    }

    #[test]
    fn test_close_channel_insufficient_balance() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();
        let sender = app.api().addr_make("sender");
        let recipient = app.api().addr_make("recipient");

        // Open channel with 1M
        let block_time = app.block_info().time.seconds();
        let open_msg = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration: block_time + 86400,
        };

        let funds = vec![Coin::new(1_000_000u128, "uakt")];
        let res = app
            .execute_contract(sender.clone(), contract.addr(), &open_msg, &funds)
            .unwrap();

        let data: serde_json::Value = serde_json::from_slice(&res.data.unwrap()).unwrap();
        let channel_id = data["channel_id"].as_str().unwrap().to_string();

        // Try to claim more than locked amount
        let claim = generate_test_claim(&channel_id, 2_000_000, 1, &TEST_PRIVATE_KEY);

        let close_msg = ExecuteMsg::CloseChannel {
            channel_id,
            final_claim: claim,
        };

        let err = app
            .execute_contract(recipient, contract.addr(), &close_msg, &[])
            .unwrap_err();

        // Should fail with InsufficientBalance
        assert!(err.to_string().contains("Insufficient balance"));
    }

    #[test]
    fn test_close_channel_replay_attack() {
        use cosmwasm_std::Coin;

        let (mut app, contract) = proper_instantiate();
        let sender = app.api().addr_make("sender");
        let recipient = app.api().addr_make("recipient");

        // Open channel
        let block_time = app.block_info().time.seconds();
        let open_msg = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration: block_time + 86400,
        };

        let funds = vec![Coin::new(1_000_000u128, "uakt")];
        let res = app
            .execute_contract(sender.clone(), contract.addr(), &open_msg, &funds)
            .unwrap();

        let data: serde_json::Value = serde_json::from_slice(&res.data.unwrap()).unwrap();
        let channel_id = data["channel_id"].as_str().unwrap().to_string();

        // First claim (nonce 1)
        let claim1 = generate_test_claim(&channel_id, 300_000, 1, &TEST_PRIVATE_KEY);

        let close_msg1 = ExecuteMsg::CloseChannel {
            channel_id: channel_id.clone(),
            final_claim: claim1.clone(),
        };

        app.execute_contract(recipient.clone(), contract.addr(), &close_msg1, &[])
            .unwrap();

        // Try to reuse same claim (replay attack)
        let close_msg2 = ExecuteMsg::CloseChannel {
            channel_id,
            final_claim: claim1,
        };

        let err = app
            .execute_contract(recipient, contract.addr(), &close_msg2, &[])
            .unwrap_err();

        // Should fail with ChannelClosed (channel already closed)
        assert!(err.to_string().contains("closed"));
    }

    // Story 3.5 Integration Tests: Query Functions

    #[test]
    fn test_query_channel_success() {
        use cosmwasm_std::coins;

        let (mut app, contract) = proper_instantiate();

        let sender = app.api().addr_make("sender");
        let recipient = app.api().addr_make("recipient");

        let block_time = app.block_info().time.seconds();
        let expiration = block_time + (30 * 24 * 60 * 60); // 30 days

        // Open a channel
        let open_msg = ExecuteMsg::OpenChannel {
            recipient: recipient.to_string(),
            expiration,
        };

        let res = app
            .execute_contract(
                sender.clone(),
                contract.addr(),
                &open_msg,
                &coins(1_000_000, "uakt"),
            )
            .unwrap();

        // Extract channel_id from response
        let data: serde_json::Value = cosmwasm_std::from_json(&res.data.unwrap()).unwrap();
        let channel_id = data["channel_id"].as_str().unwrap().to_string();

        // Query the channel
        let query_msg = QueryMsg::GetChannel {
            channel_id: channel_id.clone(),
        };

        let response: crate::msg::GetChannelResponse = app
            .wrap()
            .query_wasm_smart(contract.addr(), &query_msg)
            .unwrap();

        // Verify channel data
        assert_eq!(response.channel.id, channel_id);
        assert_eq!(response.channel.sender, sender);
        assert_eq!(response.channel.recipient, recipient);
        assert_eq!(response.channel.amount, Uint128::new(1_000_000));
        assert_eq!(response.channel.denom, "uakt");
        assert_eq!(response.channel.status, ChannelStatus::Open);
        assert_eq!(response.channel.highest_claim, Uint128::zero());
    }

    #[test]
    fn test_query_channel_not_found() {
        let (app, contract) = proper_instantiate();

        // Query non-existent channel
        let query_msg = QueryMsg::GetChannel {
            channel_id: "nonexistent_channel_id".to_string(),
        };

        let err = app
            .wrap()
            .query_wasm_smart::<crate::msg::GetChannelResponse>(contract.addr(), &query_msg)
            .unwrap_err();

        // Should contain error message
        assert!(err.to_string().contains("Channel not found"));
    }

    #[test]
    fn test_list_channels_empty() {
        let (app, contract) = proper_instantiate();

        // Query empty state
        let query_msg = QueryMsg::ListChannels {
            sender: None,
            recipient: None,
            status: None,
            limit: None,
            start_after: None,
        };

        let response: crate::msg::ListChannelsResponse = app
            .wrap()
            .query_wasm_smart(contract.addr(), &query_msg)
            .unwrap();

        // Verify empty response
        assert_eq!(response.channels.len(), 0);
        assert_eq!(response.total, 0);
    }

    #[test]
    fn test_list_channels_all() {
        use cosmwasm_std::coins;

        let (mut app, contract) = proper_instantiate();

        let sender = app.api().addr_make("sender");
        let block_time = app.block_info().time.seconds();
        let expiration = block_time + (30 * 24 * 60 * 60); // 30 days

        // Open 3 channels
        for i in 1..=3 {
            let recipient = app.api().addr_make(&format!("recipient{}", i));
            let open_msg = ExecuteMsg::OpenChannel {
                recipient: recipient.to_string(),
                expiration,
            };

            app.execute_contract(
                sender.clone(),
                contract.addr(),
                &open_msg,
                &coins(1_000_000 * i, "uakt"),
            )
            .unwrap();
        }

        // Query all channels
        let query_msg = QueryMsg::ListChannels {
            sender: None,
            recipient: None,
            status: None,
            limit: None,
            start_after: None,
        };

        let response: crate::msg::ListChannelsResponse = app
            .wrap()
            .query_wasm_smart(contract.addr(), &query_msg)
            .unwrap();

        // Verify 3 channels returned
        assert_eq!(response.channels.len(), 3);
        assert_eq!(response.total, 3);
    }

    #[test]
    fn test_list_channels_filter_sender() {
        use cosmwasm_std::coins;

        let (mut app, contract) = proper_instantiate();

        let sender_a = app.api().addr_make("senderA");
        let sender_b = app.api().addr_make("senderB");
        let recipient1 = app.api().addr_make("recipient1");
        let recipient2 = app.api().addr_make("recipient2");

        // Fund both senders
        app.init_modules(|router, _api, storage| {
            router
                .bank
                .init_balance(storage, &sender_a, coins(10_000_000_000, "uakt"))
                .unwrap();
            router
                .bank
                .init_balance(storage, &sender_b, coins(10_000_000_000, "uakt"))
                .unwrap();
        });

        let block_time = app.block_info().time.seconds();
        let expiration = block_time + (30 * 24 * 60 * 60); // 30 days

        // Open 2 channels from sender A (with different recipients to avoid channel_id collision)
        let open_msg1 = ExecuteMsg::OpenChannel {
            recipient: recipient1.to_string(),
            expiration,
        };
        app.execute_contract(
            sender_a.clone(),
            contract.addr(),
            &open_msg1,
            &coins(1_000_000, "uakt"),
        )
        .unwrap();

        let recipient1b = app.api().addr_make("recipient1b");
        let open_msg2 = ExecuteMsg::OpenChannel {
            recipient: recipient1b.to_string(),
            expiration,
        };
        app.execute_contract(
            sender_a.clone(),
            contract.addr(),
            &open_msg2,
            &coins(2_000_000, "uakt"),
        )
        .unwrap();

        // Open 1 channel from sender B
        let open_msg = ExecuteMsg::OpenChannel {
            recipient: recipient2.to_string(),
            expiration,
        };
        app.execute_contract(
            sender_b,
            contract.addr(),
            &open_msg,
            &coins(3_000_000, "uakt"),
        )
        .unwrap();

        // Query channels for sender A
        let query_msg = QueryMsg::ListChannels {
            sender: Some(sender_a.to_string()),
            recipient: None,
            status: None,
            limit: None,
            start_after: None,
        };

        let response: crate::msg::ListChannelsResponse = app
            .wrap()
            .query_wasm_smart(contract.addr(), &query_msg)
            .unwrap();

        // Verify only sender A's channels returned
        assert_eq!(response.channels.len(), 2);
        assert_eq!(response.total, 2);
        assert!(response.channels.iter().all(|c| c.sender == sender_a));
    }

    #[test]
    fn test_list_channels_filter_status() {
        use cosmwasm_std::coins;

        let (mut app, contract) = proper_instantiate();

        let sender = app.api().addr_make("sender");
        let recipient1 = app.api().addr_make("recipient1");
        let recipient2 = app.api().addr_make("recipient2");

        let block_time = app.block_info().time.seconds();
        let expiration = block_time + (30 * 24 * 60 * 60); // 30 days

        // Open 2 channels (with different recipients to avoid channel_id collision)
        let channel1_id: String;
        let open_msg1 = ExecuteMsg::OpenChannel {
            recipient: recipient1.to_string(),
            expiration,
        };
        let res1 = app
            .execute_contract(
                sender.clone(),
                contract.addr(),
                &open_msg1,
                &coins(1_000_000, "uakt"),
            )
            .unwrap();
        let data: serde_json::Value = cosmwasm_std::from_json(&res1.data.unwrap()).unwrap();
        channel1_id = data["channel_id"].as_str().unwrap().to_string();

        let open_msg2 = ExecuteMsg::OpenChannel {
            recipient: recipient2.to_string(),
            expiration,
        };
        app.execute_contract(
            sender.clone(),
            contract.addr(),
            &open_msg2,
            &coins(2_000_000, "uakt"),
        )
        .unwrap();

        // Close channel 1 using helper function
        let claim = generate_test_claim(&channel1_id, 800_000u128, 1u64, &TEST_PRIVATE_KEY);

        let close_msg = ExecuteMsg::CloseChannel {
            channel_id: channel1_id,
            final_claim: claim,
        };

        app.execute_contract(recipient1.clone(), contract.addr(), &close_msg, &[])
            .unwrap();

        // Query only Open channels
        let query_msg = QueryMsg::ListChannels {
            sender: None,
            recipient: None,
            status: Some(ChannelStatus::Open),
            limit: None,
            start_after: None,
        };

        let response: crate::msg::ListChannelsResponse = app
            .wrap()
            .query_wasm_smart(contract.addr(), &query_msg)
            .unwrap();

        // Verify only 1 Open channel returned
        assert_eq!(response.channels.len(), 1);
        assert_eq!(response.total, 1);
        assert!(response
            .channels
            .iter()
            .all(|c| c.status == ChannelStatus::Open));
    }

    #[test]
    fn test_list_channels_pagination() {
        use cosmwasm_std::coins;

        let (mut app, contract) = proper_instantiate();

        let sender = app.api().addr_make("sender");
        let block_time = app.block_info().time.seconds();
        let expiration = block_time + (30 * 24 * 60 * 60); // 30 days

        // Open 5 channels
        for i in 1..=5 {
            let recipient = app.api().addr_make(&format!("recipient{}", i));
            let open_msg = ExecuteMsg::OpenChannel {
                recipient: recipient.to_string(),
                expiration,
            };

            app.execute_contract(
                sender.clone(),
                contract.addr(),
                &open_msg,
                &coins(1_000_000 * i, "uakt"),
            )
            .unwrap();
        }

        // Query with limit 2
        let query_msg = QueryMsg::ListChannels {
            sender: None,
            recipient: None,
            status: None,
            limit: Some(2),
            start_after: None,
        };

        let response: crate::msg::ListChannelsResponse = app
            .wrap()
            .query_wasm_smart(contract.addr(), &query_msg)
            .unwrap();

        // Verify only 2 channels returned
        assert_eq!(response.channels.len(), 2);
        assert_eq!(response.total, 2);

        // Get second channel ID for pagination
        let second_channel_id = response.channels[1].id.clone();

        // Query next page with start_after
        let query_msg2 = QueryMsg::ListChannels {
            sender: None,
            recipient: None,
            status: None,
            limit: Some(2),
            start_after: Some(second_channel_id),
        };

        let response2: crate::msg::ListChannelsResponse = app
            .wrap()
            .query_wasm_smart(contract.addr(), &query_msg2)
            .unwrap();

        // Verify next 2 channels returned (different from first page)
        assert_eq!(response2.channels.len(), 2);
        assert_eq!(response2.total, 2);
        assert_ne!(response2.channels[0].id, response.channels[0].id);
        assert_ne!(response2.channels[0].id, response.channels[1].id);
    }
}
