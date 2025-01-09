module keyring::rsa_message_packing {
    use std::vector;
    use std::error;
    use aptos_std::bcs;

    /// Constants for field sizes
    const TARGET_ADDR_LEN: u64 = 20; // 20 bytes for address

    /// Create a zero-filled vector of specified length
    fun create_zero_vector(len: u64): vector<u8> {
        let result = vector::empty<u8>();
        let i = 0;
        while (i < len) {
            vector::push_back(&mut result, 0u8);
            i = i + 1;
        };
        result
    }

    /// Error codes
    const EINVALID_POLICY_ID: u64 = 1;
    const EINVALID_VALID_FROM: u64 = 2;
    const EINVALID_VALID_UNTIL: u64 = 3;
    const EINVALID_COST: u64 = 4;
    const EINVALID_ADDRESS: u64 = 5;

    /// Maximum values for fields
    const MAX_POLICY_ID: u64 = 0xFFFFFF; // 24 bits
    const MAX_VALID_TIME: u64 = 0xFFFFFFFF; // 32 bits
    const MAX_COST: u128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF; // 128 bits

    /// Pack auth message into bytes
    /// @param trading_address: The trading address (20 bytes)
    /// @param policy_id: The policy ID (24 bits)
    /// @param valid_from: Start time (32 bits)
    /// @param valid_until: End time (32 bits)
    /// @param cost: Cost value (128 bits)
    /// @param backdoor: Additional backdoor data
    public fun pack_auth_message(
        trading_address: address,
        policy_id: u64,
        valid_from: u64,
        valid_until: u64,
        cost: u128,
        backdoor: vector<u8>
    ): vector<u8> {
        // Validate field sizes
        assert!(policy_id <= MAX_POLICY_ID, error::invalid_argument(EINVALID_POLICY_ID));
        assert!(valid_from <= MAX_VALID_TIME, error::invalid_argument(EINVALID_VALID_FROM));
        assert!(valid_until <= MAX_VALID_TIME, error::invalid_argument(EINVALID_VALID_UNTIL));
        assert!(cost <= MAX_COST, error::invalid_argument(EINVALID_COST));

        // Create output vector
        let mut result = vector::empty<u8>();

        // Add trading address (20 bytes) in big-endian format
        // Convert address to bytes (32 bytes) and take first 20 bytes
        let addr_bytes = bcs::to_bytes(&trading_address);
        let len = vector::length(&addr_bytes);
        assert!(len > 0, error::invalid_argument(EINVALID_ADDRESS));
        
        // Create zero-filled result vector for address (20 bytes)
        let result = create_zero_vector(TARGET_ADDR_LEN);
        
        // Get address bytes after BCS length prefix
        let addr_bytes_len = vector::length(&addr_bytes);
        if (addr_bytes_len > 1) {
            let available_bytes = addr_bytes_len - 1;
            let bytes_to_copy = if (available_bytes > TARGET_ADDR_LEN) TARGET_ADDR_LEN else available_bytes;
            
            let i = 0;
            while (i < bytes_to_copy) {
                let src_byte = *vector::borrow(&addr_bytes, i + 1);
                let dst_ref = vector::borrow_mut(&mut result, i);
                *dst_ref = src_byte;
                i = i + 1;
            };
        };
        
        // Add padding byte (0)
        vector::push_back(&mut result, 0u8);
        
        // Add policy ID (3 bytes = 24 bits)
        vector::push_back(&mut result, ((policy_id >> 16) & 0xFF) as u8);
        vector::push_back(&mut result, ((policy_id >> 8) & 0xFF) as u8);
        vector::push_back(&mut result, (policy_id & 0xFF) as u8);
        
        // Add valid_from (4 bytes = 32 bits)
        vector::push_back(&mut result, ((valid_from >> 24) & 0xFF) as u8);
        vector::push_back(&mut result, ((valid_from >> 16) & 0xFF) as u8);
        vector::push_back(&mut result, ((valid_from >> 8) & 0xFF) as u8);
        vector::push_back(&mut result, (valid_from & 0xFF) as u8);
        
        // Add valid_until (4 bytes = 32 bits)
        vector::push_back(&mut result, ((valid_until >> 24) & 0xFF) as u8);
        vector::push_back(&mut result, ((valid_until >> 16) & 0xFF) as u8);
        vector::push_back(&mut result, ((valid_until >> 8) & 0xFF) as u8);
        vector::push_back(&mut result, (valid_until & 0xFF) as u8);
        
        // Add cost (20 bytes = 160 bits, padded from 128 bits)
        let i = 19;
        while (i >= 0) {
            vector::push_back(&mut result, ((cost >> (i * 8)) & 0xFF) as u8);
            if (i == 0) { break };
            i = i - 1;
        };
        
        // Add backdoor data
        vector::append(&mut result, backdoor);
        
        result
    }
}
