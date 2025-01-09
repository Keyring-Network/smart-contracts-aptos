#[test_only]
module keyring::rsa_verify_tests {
    use std::vector;
    use std::debug;
    use keyring::rsa_verify;
    use keyring::rsa_message_packing;

    // Test vector constants
    struct TestVector has copy, drop {
        trading_address: address,
        policy_id: u256,
        create_before: u256,
        valid_until: u256,
        cost: u256,
        backdoor: vector<u8>,
        key: vector<u8>,
        signature: vector<u8>,
        expected: bool
    }

    fun test_vector_1(): TestVector {
        TestVector {
            trading_address: @0x0123456789abcDEF0123456789abCDef01234567,
            policy_id: 123456,
            create_before: 1625247600,
            valid_until: 1627849600,
            cost: 1000000000000000000,
            backdoor: x"6578616d706c655f6261636b646f6f725f64617461",
            key: x"ab067f172127a5f2611960c158f33de52ae940c7313d0c3ad95031d5a7a86142ea8f2500f4206d1c67087d4c60e0046c723f07aef45156d42f7155a461dcafb3cf3d2fa6b8cb77d8abecd834c9cf9769709414d85a5030f161e512981cf4534f3c6ea19286f08e53affa0155b5e9376efefb34a38bd8d8168bd0ba63542aa933",
            signature: x"52646d189f3467cab366080801ad7e9903a98077ddd83a9e574d1596b0361c027b1419bf655b8b84a4a4691a5bca9cb0be012b52816d4d6411b9cbd9d9070a3dc4167f14423c7f4f508d0a1e853c75dc3ff89d8a25b890409d2b9044954bcd58dbe255380ff3443197b67580421281ba3caaf96bb555636d686180e1457a15d3",
            expected: true
        }
    }

    fun test_vector_2(): TestVector {
        // Test vector with maximum values for fields
        TestVector {
            trading_address: @0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
            policy_id: 0xFFFFFF, // Max 24 bits
            create_before: 0xFFFFFFFF, // Max 32 bits
            valid_until: 0xFFFFFFFF, // Max 32 bits
            cost: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, // Max 128 bits
            backdoor: x"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            // Using same key/signature pair since we know it's valid
            key: x"ab067f172127a5f2611960c158f33de52ae940c7313d0c3ad95031d5a7a86142ea8f2500f4206d1c67087d4c60e0046c723f07aef45156d42f7155a461dcafb3cf3d2fa6b8cb77d8abecd834c9cf9769709414d85a5030f161e512981cf4534f3c6ea19286f08e53affa0155b5e9376efefb34a38bd8d8168bd0ba63542aa933",
            signature: x"52646d189f3467cab366080801ad7e9903a98077ddd83a9e574d1596b0361c027b1419bf655b8b84a4a4691a5bca9cb0be012b52816d4d6411b9cbd9d9070a3dc4167f14423c7f4f508d0a1e853c75dc3ff89d8a25b890409d2b9044954bcd58dbe255380ff3443197b67580421281ba3caaf96bb555636d686180e1457a15d3",
            expected: false // Should fail since message data is different
        }
    }

    // Standard RSA exponent e=65537
    const RSA_E: vector<u8> = x"010001";

    fun verify_test_vector(test_data: TestVector): bool {
        let TestVector {
            trading_address,
            policy_id,
            create_before,
            valid_until,
            cost,
            backdoor,
            key: key_bytes,
            signature,
            expected: _
        } = test_data;

        // Create RSA key
        let key = rsa_verify::create_key(RSA_E, key_bytes);

        // Pack message data
        let message = rsa_message_packing::pack_auth_message(
            trading_address,
            policy_id,
            create_before,
            valid_until,
            cost,
            backdoor
        );

        // Verify signature
        rsa_verify::verify_auth_message(message, signature, key)
    }

    #[test]
    public fun test_verify_auth_message_vector_1() {
        let test_data = test_vector_1();
        let TestVector {
            trading_address: _,
            policy_id: _,
            create_before: _,
            valid_until: _,
            cost: _,
            backdoor: _,
            key: _,
            signature: _,
            expected
        } = copy test_data;
        let result = verify_test_vector(test_data);
        // Print debug info for message packing
        // Print debug info for message packing
        std::debug::print(&b"=== Test Vector 1 Debug Info ===");
        std::debug::print(&b"Result:");
        std::debug::print(&result);
        std::debug::print(&b"Expected:");
        std::debug::print(&expected);
        
        // Print the packed message components for debugging
        let message = rsa_message_packing::pack_auth_message(
            TRADING_ADDRESS,
            POLICY_ID,
            CREATE_BEFORE,
            VALID_UNTIL,
            COST,
            BACKDOOR_HEX
        );
        std::debug::print(&b"Packed message bytes:");
        std::debug::print(&message);
        assert!(result == expected, 0);
    }

    #[test]
    public fun test_verify_auth_message_vector_2() {
        let test_data = test_vector_2();
        let TestVector {
            trading_address: _,
            policy_id: _,
            create_before: _,
            valid_until: _,
            cost: _,
            backdoor: _,
            key: _,
            signature: _,
            expected
        } = copy test_data;
        let result = verify_test_vector(test_data);
        assert!(result == expected, 0);
    }

    #[test]
    public fun test_verify_auth_message_invalid_signature() {
        let TestVector {
            trading_address,
            policy_id,
            create_before,
            valid_until,
            cost,
            backdoor,
            key: key_bytes,
            signature,
            expected: _
        } = test_vector_1();
        
        // Create invalid signature by modifying one byte
        let invalid_sig = copy signature;
        let first_byte = vector::borrow_mut(&mut invalid_sig, 0);
        *first_byte = *first_byte ^ 0xFF;

        // Create key and pack message
        let key = rsa_verify::create_key(RSA_E, key_bytes);
        let message = rsa_message_packing::pack_auth_message(
            trading_address,
            policy_id,
            create_before,
            valid_until,
            cost,
            backdoor
        );

        // Verify signature should fail
        let result = rsa_verify::verify_auth_message(message, invalid_sig, key);
        assert!(result == false, 0);
    }
}
