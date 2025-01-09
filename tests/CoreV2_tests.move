#[test_only]
module keyring::core_v2_tests {
    use std::signer;
    use aptos_framework::timestamp;
    use aptos_framework::account;
    // No debug import needed for assertions
    use keyring::core_v2;

    // Test constants
    const POLICY_ID: u64 = 123456;
    const VALID_FROM: u64 = 1625247600;
    const VALID_UNTIL: u64 = 1627849600;
    const COST: u128 = 1000000000000000000;
    const BACKDOOR: vector<u8> = x"6578616d706c655f6261636b646f6f725f64617461";
    const KEY: vector<u8> = x"ab067f172127a5f2611960c158f33de52ae940c7313d0c3ad95031d5a7a86142ea8f2500f4206d1c67087d4c60e0046c723f07aef45156d42f7155a461dcafb3cf3d2fa6b8cb77d8abecd834c9cf9769709414d85a5030f161e512981cf4534f3c6ea19286f08e53affa0155b5e9376efefb34a38bd8d8168bd0ba63542aa933";
    const SIGNATURE: vector<u8> = x"52646d189f3467cab366080801ad7e9903a98077ddd83a9e574d1596b0361c027b1419bf655b8b84a4a4691a5bca9cb0be012b52816d4d6411b9cbd9d9070a3dc4167f14423c7f4f508d0a1e853c75dc3ff89d8a25b890409d2b9044954bcd58dbe255380ff3443197b67580421281ba3caaf96bb555636d686180e1457a15d3";

    #[test]
    fun test_init_module() {
        // Create test account and initialize timestamp
        let admin = account::create_account_for_test(@0x1);
        timestamp::set_time_has_started_for_testing(&admin);
        
        // Initialize module
        core_v2::init_for_test(&admin);
        
        // Verify admin capability exists
        assert!(core_v2::has_admin_cap(signer::address_of(&admin)), 0);
    }

    #[test]
    fun test_register_key() {
        // Create test account and initialize module
        let admin = account::create_account_for_test(@0x1);
        timestamp::set_time_has_started_for_testing(&admin);
        core_v2::init_for_test(&admin);
        
        // Register key
        core_v2::register_key(&admin, VALID_FROM, VALID_UNTIL, KEY);
        
        // Verify key is registered
        assert!(core_v2::is_key_valid(signer::address_of(&admin)), 1);
    }

    #[test]
    fun test_create_credential() {
        // Create test accounts
        let admin = account::create_account_for_test(@0x1);
        let trading_address = @0x2;
        timestamp::set_time_has_started_for_testing(&admin);
        
        // Initialize module and register key
        core_v2::init_for_test(&admin);
        core_v2::register_key(&admin, VALID_FROM, VALID_UNTIL, KEY);
        
        // Create credential
        core_v2::create_credential(
            &admin,
            trading_address,
            POLICY_ID,
            VALID_FROM,
            VALID_UNTIL,
            COST,
            KEY,
            SIGNATURE,
            BACKDOOR
        );
        
        // Verify credential
        assert!(core_v2::check_credential(
            trading_address,
            POLICY_ID,
            timestamp::now_seconds(),
            COST,
            KEY,
            SIGNATURE,
            BACKDOOR
        ), 1);
    }

    #[test]
    fun test_blacklist_entity() {
        // Create test accounts
        let admin = account::create_account_for_test(@0x1);
        let entity = @0x2;
        timestamp::set_time_has_started_for_testing(&admin);
        
        // Initialize module
        core_v2::init_for_test(&admin);
        
        // Blacklist entity
        core_v2::blacklist_entity(&admin, POLICY_ID, entity, true);
        
        // Verify entity is blacklisted
        assert!(!core_v2::check_credential(
            entity,
            POLICY_ID,
            timestamp::now_seconds(),
            COST,
            KEY,
            SIGNATURE,
            BACKDOOR
        ), 1);
    }

    #[test]
    fun test_revoke_key() {
        // Create test account and initialize module
        let admin = account::create_account_for_test(@0x1);
        timestamp::set_time_has_started_for_testing(&admin);
        core_v2::init_for_test(&admin);
        
        // Register and then revoke key
        core_v2::register_key(&admin, VALID_FROM, VALID_UNTIL, KEY);
        core_v2::revoke_key(&admin, signer::address_of(&admin));
        
        // Verify key is revoked
        assert!(!core_v2::is_key_valid(signer::address_of(&admin)), 1);
    }
}
