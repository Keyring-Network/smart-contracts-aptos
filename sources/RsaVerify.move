module keyring::rsa_verify {
    use std::vector;
    use aptos_framework::crypto_algebra;
    use aptos_framework::hash;

    /// Constants for SHA256 parameter encoding
    const SHA256_EXPLICIT_NULL_PARAM_LEN: u64 = 17;
    const SHA256_IMPLICIT_NULL_PARAM_LEN: u64 = 15;

    /// SHA256 algorithm identifiers
    const SHA256_EXPLICIT_NULL_PARAM: vector<u8> = vector[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00
    ];
    const SHA256_IMPLICIT_NULL_PARAM: vector<u8> = vector[
        0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
    ];

    /// Error codes
    const EINVALID_SIGNATURE_LENGTH: u64 = 1;
    const EINVALID_PADDING: u64 = 2;
    const EINVALID_DIGEST_ALGO: u64 = 3;
    const EINVALID_HASH: u64 = 4;

    /// Struct to hold RSA key components
    struct RsaKey has copy, drop, store {
        exponent: vector<u8>,
        modulus: vector<u8>
    }

    /// Create a new RSA key
    public fun create_key(exponent: vector<u8>, modulus: vector<u8>): RsaKey {
        RsaKey {
            exponent,
            modulus
        }
    }

    /// Verify a PKCS1 SHA256 signature
    /// @param data: The data to verify
    /// @param signature: The signature bytes
    /// @param key: The RSA public key
    /// @return: true if verification succeeds, false otherwise
    public fun verify_auth_message(
        data: vector<u8>,
        signature: vector<u8>,
        key: RsaKey
    ): bool {
        // First compute SHA256 of data
        let message_hash = hash::sha2_256(data);
        
        // Then verify the PKCS1 SHA256 signature
        pkcs1_sha256(message_hash, signature, key.exponent, key.modulus)
    }

    /// Internal function to verify PKCS1 SHA256 signature
    /// This replicates the logic of pkcs1Sha256 from RsaVerifyOptimized.sol
    fun pkcs1_sha256(
        message_hash: vector<u8>,
        signature: vector<u8>,
        exponent: vector<u8>,
        modulus: vector<u8>
    ): bool {
        // Check minimum length requirement (512 bits = 64 bytes)
        let modulus_len = vector::length(&modulus);
        if (modulus_len < 64) {
            return false
        };

        // Check signature length matches modulus length
        if (vector::length(&signature) != modulus_len) {
            return false
        };

        // Perform RSA decryption (modular exponentiation)
        let decipher = mod_exp(signature, exponent, modulus);
        
        // Verify PKCS1 v1.5 padding format:
        // 0x00 || 0x01 || PS || 0x00 || DigestInfo
        // Where PS is padding filled with 0xff
        
        // Check initial bytes (0x00 || 0x01)
        if (*vector::borrow(&decipher, 0) != 0x00 || *vector::borrow(&decipher, 1) != 0x01) {
            return false
        };
        
        // Find DigestInfo by scanning for 0x00 byte after padding
        let copy i = 2;
        loop {
            if (i >= vector::length(&decipher)) {
                break
            };
            if (*vector::borrow(&decipher, i) == 0x00) {
                break
            };
            if (*vector::borrow(&decipher, i) != 0xff) {
                return false
            };
            i = i + 1;
        };
        
        // Verify minimum padding length (8 bytes as per PKCS#1 v1.5)
        if (i < 10) {
            return false
        };
        
        // Skip the 0x00 separator byte
        i = i + 1;
        
        // Check SHA256 algorithm identifier
        let mut has_explicit_param = false;
        let mut has_implicit_param = false;
        
        // Try explicit parameters
        if (i + SHA256_EXPLICIT_NULL_PARAM_LEN <= vector::length(&decipher)) {
            has_explicit_param = true;
            let mut j = 0;
            while (j < SHA256_EXPLICIT_NULL_PARAM_LEN) {
                if (*vector::borrow(&decipher, i + j) != *vector::borrow(&SHA256_EXPLICIT_NULL_PARAM, j)) {
                    has_explicit_param = false;
                    break
                };
                j = j + 1;
            };
        };
        
        // Try implicit parameters if explicit failed
        if (!has_explicit_param && i + SHA256_IMPLICIT_NULL_PARAM_LEN <= vector::length(&decipher)) {
            has_implicit_param = true;
            let mut j = 0;
            while (j < SHA256_IMPLICIT_NULL_PARAM_LEN) {
                if (*vector::borrow(&decipher, i + j) != *vector::borrow(&SHA256_IMPLICIT_NULL_PARAM, j)) {
                    has_implicit_param = false;
                    break
                };
                j = j + 1;
            };
        };
        
        if (!has_explicit_param && !has_implicit_param) {
            return false
        };
        
        // Move past algorithm identifier
        i = i + if (has_explicit_param) SHA256_EXPLICIT_NULL_PARAM_LEN else SHA256_IMPLICIT_NULL_PARAM_LEN;
        
        // Check hash marker (0x04 || 0x20 for 32-byte SHA256)
        if (*vector::borrow(&decipher, i) != 0x04 || *vector::borrow(&decipher, i + 1) != 0x20) {
            return false
        };
        i = i + 2;
        
        // Finally verify the message hash
        if (i + 32 > vector::length(&decipher)) {
            return false
        };
        
        let mut j = 0;
        while (j < 32) {
            if (*vector::borrow(&decipher, i + j) != *vector::borrow(&message_hash, j)) {
                return false
            };
            j = j + 1;
        };
        
        true
    }

    /// Helper function to perform modular exponentiation
    /// This replaces the precompiled contract call in Solidity
    /// Uses the square-and-multiply algorithm for modular exponentiation
    fun mod_exp(
        base: vector<u8>,
        exponent: vector<u8>,
        modulus: vector<u8>
    ): vector<u8> {
        // Convert inputs to u256 representation (as vectors of u64)
        let base_int = bytes_to_u256(&base);
        let exp_int = bytes_to_u256(&exponent);
        let mod_int = bytes_to_u256(&modulus);
        
        // Initialize result to 1
        let result = vector<u64>[1, 0, 0, 0];
        let base_val = base_int;
        
        // Square and multiply algorithm
        let i = 0;
        let exp_bytes = vector::length(&exponent);
        while (i < exp_bytes * 8) {
            // Square
            result = mod_mul_u256(&result, &result, &mod_int);
            
            // Multiply if bit is set
            if (get_bit(&exp_int, i)) {
                result = mod_mul_u256(&result, &base_val, &mod_int);
            };
            
            i = i + 1;
        };
        
        // Convert result back to bytes
        u256_to_bytes(&result)
    }
    
    /// Convert bytes to u256 (represented as vector of 4 u64)
    fun bytes_to_u256(bytes: &vector<u8>): vector<u64> {
        let result = vector<u64>[0, 0, 0, 0];
        let i = 0;
        let len = vector::length(bytes);
        
        while (i < len && i < 32) {
            let byte = *vector::borrow(bytes, i);
            let word_idx = i / 8;
            let bit_pos = (i % 8) * 8;
            let val = (byte as u64) << bit_pos;
            
            let current = vector::borrow_mut(&mut result, word_idx);
            *current = *current | val;
            
            i = i + 1;
        };
        
        result
    }
    
    /// Convert u256 back to bytes
    fun u256_to_bytes(val: &vector<u64>): vector<u8> {
        let result = vector::empty<u8>();
        let i = 0;
        
        while (i < 32) {
            let word_idx = i / 8;
            let byte_pos = (i % 8) * 8;
            let word = *vector::borrow(val, word_idx);
            let byte = ((word >> byte_pos) & 0xFF as u64) as u8;
            vector::push_back(&mut result, byte);
            i = i + 1;
        };
        
        result
    }
    
    /// Get bit at position i from u256
    fun get_bit(val: &vector<u64>, i: u64): bool {
        let word_idx = i / 64;
        let bit_pos = i % 64;
        let word = *vector::borrow(val, (word_idx as u64));
        ((word >> bit_pos) & 1) == 1
    }
    
    /// Modular multiplication for u256 values
    /// Uses the standard schoolbook multiplication algorithm with reduction
    fun mod_mul_u256(a: &vector<u64>, b: &vector<u64>, m: &vector<u64>): vector<u64> {
        let result = vector<u64>[0, 0, 0, 0];
        let i = 0;
        
        // Perform multiplication one word at a time
        while (i < 4) {
            let j = 0;
            let carry = 0u64;
            let a_word = *vector::borrow(a, i);
            
            while (j < 4) {
                let b_word = *vector::borrow(b, j);
                let pos = i + j;
                if (pos < 4) {
                    let current = vector::borrow_mut(&mut result, pos);
                    let product = (a_word as u128) * (b_word as u128) + (carry as u128) + (*current as u128);
                    *current = (product & 0xFFFFFFFFFFFFFFFF) as u64;
                    carry = (product >> 64) as u64;
                };
                j = j + 1;
            };
            i = i + 1;
        };
        
        // Perform modular reduction
        mod_reduce_u256(&mut result, m);
        result
    }
    
    /// Modular reduction for u256 values
    /// Uses repeated subtraction for simplicity
    fun mod_reduce_u256(value: &mut vector<u64>, modulus: &vector<u64>) {
        while (compare_u256(value, modulus) >= 0) {
            let i = 3;
            let borrow = 0i128;
            
            while (i >= 0) {
                let v = *vector::borrow(value, (i as u64));
                let m = *vector::borrow(modulus, (i as u64));
                let diff = (v as i128) - (m as i128) - borrow;
                let current = vector::borrow_mut(value, (i as u64));
                
                if (diff < 0) {
                    *current = ((1u128 << 64) as u64) + (diff as u64);
                    borrow = 1;
                } else {
                    *current = diff as u64;
                    borrow = 0;
                };
                
                if (i == 0) { break };
                i = i - 1;
            };
        }
    }
    
    /// Compare two u256 values
    /// Returns -1 if a < b, 0 if a == b, 1 if a > b
    fun compare_u256(a: &vector<u64>, b: &vector<u64>): i8 {
        let i = 3;
        while (i >= 0) {
            let a_word = *vector::borrow(a, (i as u64));
            let b_word = *vector::borrow(b, (i as u64));
            if (a_word > b_word) {
                return 1
            };
            if (a_word < b_word) {
                return -1
            };
            if (i == 0) { break };
            i = i - 1;
        };
        0
    }
    }
}
