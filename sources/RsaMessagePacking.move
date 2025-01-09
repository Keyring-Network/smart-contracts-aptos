module keyring::rsa_message_packing {
    use std::vector;
    use std::error;
    use aptos_std::bcs;

    /// Constants for field sizes
    const TARGET_ADDR_LEN: u64 = 20; // 20 bytes for address

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

        // Add trading address (20 bytes) in big-endian format
        // Convert address to bytes and extract last 20 bytes
        let addr_bytes = bcs::to_bytes(&trading_address);
        
        // Debug print address bytes
        std::debug::print(&b"BCS encoded address bytes:");
        std::debug::print(&addr_bytes);
        
        // Create result vector for address bytes
        let result = vector::empty<u8>();
        
        // Extract last 20 bytes of the address in big-endian order
        let addr_len = vector::length(&addr_bytes);
        let start = if (addr_len >= TARGET_ADDR_LEN) { addr_len - TARGET_ADDR_LEN } else { 0 };
        let i = 0;
        while (i < TARGET_ADDR_LEN && start + i < addr_len) {
            vector::push_back(&mut result, *vector::borrow(&addr_bytes, start + i));
            i = i + 1;
        };
        
        // Pad with zeros if needed (should be at the start for big-endian)
        while (vector::length(&result) < TARGET_ADDR_LEN) {
            vector::insert(&mut result, 0, 0u8);
        };
        
        // Debug print final result
        std::debug::print(&b"Final address bytes:");
        std::debug::print(&result);
        
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
        // First add padding bytes (all zeros for the high bits)
        let i = 19;
        while (i >= 16) {
            vector::push_back(&mut result, 0u8);
            i = i - 1;
        };
        
        // Then add the actual 128-bit value bytes
        // Extract bytes using division and modulo with a recursive helper
        extract_bytes(cost, i, &mut result);
        
        // Add backdoor data
        vector::append(&mut result, backdoor);
        
        result
    }

    /// Helper function to extract bytes from a u128 value
    fun extract_bytes(value: u128, index: u64, result: &mut vector<u8>) {
        if (index == 0) {
            vector::push_back(result, (value & 0xFFu128) as u8);
            return
        };
        
        let divisor = 256u128;
        let byte = (value % divisor) as u8;
        extract_bytes(value / divisor, index - 1, result);
        vector::push_back(result, byte);
    }
}
