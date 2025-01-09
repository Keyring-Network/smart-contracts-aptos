module keyring::rsa_verify {
    use std::vector;
    use aptos_framework::hash;

    /// Error codes for arithmetic operations
    const EINVALID_LENGTH: u64 = 5;
    const EINVALID_MODULUS: u64 = 6;

    /// Constants for byte operations
    const U64_BYTES: u64 = 8;
    const U256_BYTES: u64 = 32;
    const U256_BITS: u64 = 256;

    /// Constants for SHA256 parameter encoding
    const SHA256_HASH_LEN: u64 = 32;  // Length of SHA256 hash (256 bits = 32 bytes)
    
    /// ASN.1 DER encoding for SHA256 algorithm identifier
    // The complete ASN.1 DER structure for SHA256 with NULL parameters is:
    // SEQUENCE {
    //   SEQUENCE {
    //     OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1 (sha256)
    //     NULL
    //   }
    // }
    // ASN.1 DER structure for SHA256 algorithm identifier
    const SHA256_ALGORITHM_ID: vector<u8> = x"300d060960864801650304020105000420";
    // The structure is:
    // 30 0d - SEQUENCE, length 13
    //   06 09 - OID, length 9
    //     60 86 48 01 65 03 04 02 01 - SHA256 OID (2.16.840.1.101.3.4.2.1)
    //   05 00 - NULL
    //   04 20 - OCTET STRING tag (04) and length (32 bytes = 0x20)
    const SHA256_ALGORITHM_ID_LEN: u64 = 19;  // Length including SEQUENCE + OID + NULL + OCTET STRING tag + length
    const OCTET_STRING_TAG_LEN: u64 = 2;  // Length of OCTET STRING tag (04) and length byte (20)

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

    /// Get the modulus of an RSA key
    public fun get_modulus(key: &RsaKey): vector<u8> {
        key.modulus
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
        std::debug::print(&b"Modulus length:");
        std::debug::print(&modulus_len);
        if (modulus_len < 64) {
            std::debug::print(&b"Modulus too short");
            return false
        };

        // Check signature length matches modulus length
        std::debug::print(&b"Signature length:");
        std::debug::print(&vector::length(&signature));
        if (vector::length(&signature) != modulus_len) {
            std::debug::print(&b"Signature length mismatch");
            return false
        };

        // Perform RSA decryption (modular exponentiation)
        let decipher = mod_exp(signature, exponent, modulus);
        std::debug::print(&b"Decrypted bytes:");
        std::debug::print(&decipher);
        
        // Verify PKCS1 v1.5 padding format:
        // 0x00 || 0x01 || PS || 0x00 || DigestInfo
        // Where PS is padding filled with 0xff
        
        // Check initial bytes (0x00 || 0x01)
        std::debug::print(&b"Initial bytes:");
        std::debug::print(&(*vector::borrow(&decipher, 0)));
        std::debug::print(&(*vector::borrow(&decipher, 1)));
        if (*vector::borrow(&decipher, 0) != 0x00 || *vector::borrow(&decipher, 1) != 0x01) {
            std::debug::print(&b"Invalid initial bytes");
            return false
        };
        
        // Find DigestInfo by scanning for 0x00 byte after padding
        // Find end of padding by scanning for 0x00 byte
        if (!scan_padding(&decipher)) {
            return false
        };
        
        // Get padding length and verify minimum (8 bytes as per PKCS#1 v1.5)
        let padding_length = get_padding_length(&decipher);
        if (padding_length < 10) {
            return false
        };
        
        // Check SHA256 algorithm identifier
        std::debug::print(&b"Padding length:");
        std::debug::print(&padding_length);
        let has_explicit = check_sha256_params(&decipher, padding_length + 1, true);
        std::debug::print(&b"Has explicit params:");
        std::debug::print(&has_explicit);
        
        if (!has_explicit) {
            std::debug::print(&b"Invalid SHA256 params");
            return false
        };
        
        // Calculate start of ASN.1 structure (after padding)
        let asn1_start = padding_length + 1;  // Start after padding and separator byte
        std::debug::print(&b"ASN.1 structure start:");
        std::debug::print(&asn1_start);
        
        // Verify we have enough bytes for algorithm identifier and hash
        if (asn1_start + SHA256_ALGORITHM_ID_LEN + SHA256_HASH_LEN > vector::length(&decipher)) {
            std::debug::print(&b"Not enough bytes for algorithm ID and hash");
            return false
        };
        
        // Verify the ASN.1 structure matches exactly
        let i = 0;
        while (i < SHA256_ALGORITHM_ID_LEN) {
            if (*vector::borrow(&decipher, asn1_start + i) != *vector::borrow(&SHA256_ALGORITHM_ID, i)) {
                std::debug::print(&b"ASN.1 structure mismatch at index:");
                std::debug::print(&i);
                return false
            };
            i = i + 1;
        };
        
        // Extract hash starting after the complete ASN.1 structure (including OCTET STRING tag)
        let hash_start = asn1_start + SHA256_ALGORITHM_ID_LEN + OCTET_STRING_TAG_LEN;
        let extracted_hash = vector::empty();
        let i = 0;
        while (i < SHA256_HASH_LEN) {
            vector::push_back(&mut extracted_hash, *vector::borrow(&decipher, hash_start + i));
            i = i + 1;
        };
        
        std::debug::print(&b"Extracted hash:");
        std::debug::print(&extracted_hash);
        std::debug::print(&b"Expected hash:");
        std::debug::print(&message_hash);
        
        // Compare extracted hash with computed hash
        let i = 0;
        while (i < SHA256_HASH_LEN) {
            let extracted_byte = *vector::borrow(&extracted_hash, i);
            let expected_byte = *vector::borrow(&message_hash, i);
            if (extracted_byte != expected_byte) {
                std::debug::print(&b"Hash mismatch at index:");
                std::debug::print(&i);
                std::debug::print(&b"Expected:");
                std::debug::print(&expected_byte);
                std::debug::print(&b"Got:");
                std::debug::print(&extracted_byte);
                return false
            };
            i = i + 1;
        };
        
        true
    }

    /// Helper function to verify hash matches recursively
    fun verify_hash_match(decipher: &vector<u8>, d_start: u64, hash: &vector<u8>, index: u64): bool {
        if (index >= 32) {
            true
        } else {
            let decipher_byte = *vector::borrow(decipher, d_start + index);
            let hash_byte = *vector::borrow(hash, index);
            if (decipher_byte != hash_byte) {
                false
            } else {
                verify_hash_match(decipher, d_start, hash, index + 1)
            }
        }
    }

    /// Helper function to perform modular exponentiation
    /// This replaces the precompiled contract call in Solidity
    fun mod_exp(
        base: vector<u8>,
        exponent: vector<u8>,
        modulus: vector<u8>
    ): vector<u8> {
        // Convert inputs to u256 representation
        let base_val = bytes_to_u256(&base);
        let exp_val = bytes_to_u256(&exponent);
        let mod_val = bytes_to_u256(&modulus);
        
        // Initialize result to 1
        let result = vector<u64>[1, 0, 0, 0];
        let i = 255; // Start from most significant bit
        
        // Square and multiply algorithm
        while (i >= 0) {
            // Square step
            result = mod_mul_u256(&result, &result, &mod_val);
            
            // Multiply step (if current bit is 1)
            if (get_bit(&exp_val, i)) {
                result = mod_mul_u256(&result, &base_val, &mod_val);
            };
            
            if (i == 0) { break };
            i = i - 1;
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
            let bit_pos = ((i % 8) * 8) as u8;
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
            let byte_pos = ((i % 8) * 8) as u8;
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
        let bit_pos = (i % 64) as u8;
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
            let _mut_borrow = false;
            
            while (i >= 0) {
                let v = *vector::borrow(value, (i as u64));
                let m = *vector::borrow(modulus, (i as u64));
                
                // Handle existing borrow
                let v_adjusted = if (_mut_borrow && v == 0) {
                    _mut_borrow = true;
                    0xFFFFFFFFFFFFFFFF
                } else if (_mut_borrow) {
                    _mut_borrow = false;
                    v - 1
                } else {
                    v
                };
                
                // Perform subtraction with potential new borrow
                let (result, new_borrow) = if (v_adjusted >= m) {
                    (v_adjusted - m, false)
                } else {
                    // Use u128 for intermediate calculation
                    let v_big = ((v_adjusted as u128) + (1u128 << 64));
                    let m_big = (m as u128);
                    ((v_big - m_big) as u64, true)
                };
                
                let current = vector::borrow_mut(value, (i as u64));
                *current = result;
                _mut_borrow = new_borrow;
                
                if (i == 0) { break };
                i = i - 1;
            };
        }
    }
    
    /// Compare two u256 values
    /// Returns -1 if a < b, 0 if a == b, 1 if a > b
    fun compare_u256(a: &vector<u64>, b: &vector<u64>): u8 {
        let i = 3;
        while (i >= 0) {
            let a_word = *vector::borrow(a, (i as u64));
            let b_word = *vector::borrow(b, (i as u64));
            if (a_word > b_word) {
                return 1
            };
            if (a_word < b_word) {
                return 2 // Using 2 to represent -1
            };
            if (i == 0) { break };
            i = i - 1;
        };
        0
    }

    /// Helper function to scan padding recursively
    fun scan_padding(decipher: &vector<u8>): bool {
        let found_separator = false;
        let i = 2;  // Start after 0x00 0x01
        let len = vector::length(decipher);
        
        scan_padding_loop(decipher, i, len, found_separator)
    }

    fun scan_padding_loop(decipher: &vector<u8>, i: u64, len: u64, found_separator: bool): bool {
        if (i >= len) {
            found_separator
        } else {
            let current_byte = *vector::borrow(decipher, i);
            if (!found_separator) {
                if (current_byte == 0x00) {
                    // Found separator, continue scanning to verify remaining bytes
                    scan_padding_loop(decipher, i + 1, len, true)
                } else if (current_byte != 0xff) {
                    false  // Invalid padding
                } else {
                    // Valid padding byte, continue scanning
                    scan_padding_loop(decipher, i + 1, len, false)
                }
            } else {
                // After separator, continue scanning to verify DigestInfo
                scan_padding_loop(decipher, i + 1, len, true)
            }
        }
    }

    /// Helper function to get padding length
    fun get_padding_length(decipher: &vector<u8>): u64 {
        let len = vector::length(decipher);
        find_separator_index(decipher, 2, len)
    }

    /// Helper function to find separator index recursively
    fun find_separator_index(decipher: &vector<u8>, index: u64, len: u64): u64 {
        if (index >= len) {
            len
        } else if (*vector::borrow(decipher, index) == 0x00) {
            index
        } else {
            find_separator_index(decipher, index + 1, len)
        }
    }

    /// Helper function to check SHA256 parameters and hash marker
    fun check_sha256_params(decipher: &vector<u8>, start_index: u64, _explicit: bool): bool {
        // We only support explicit parameters in this implementation
        let total_len = SHA256_ALGORITHM_ID_LEN + SHA256_HASH_LEN;
        
        std::debug::print(&b"Checking SHA256 params at index:");
        std::debug::print(&start_index);
        std::debug::print(&b"Expected algorithm ID:");
        std::debug::print(&SHA256_ALGORITHM_ID);
        
        if (start_index + total_len > vector::length(decipher)) {
            std::debug::print(&b"Total length exceeds decipher length");
            return false
        };
            
        // Extract actual params for debugging
        let actual_params = vector::empty();
        let i = 0;
        while (i < SHA256_ALGORITHM_ID_LEN) {
            vector::push_back(&mut actual_params, *vector::borrow(decipher, start_index + i));
            i = i + 1;
        };
        std::debug::print(&b"Actual params:");
        std::debug::print(&actual_params);
        
        // Compare algorithm ID and parameters
        let i = 0;
        while (i < SHA256_ALGORITHM_ID_LEN) {
            if (*vector::borrow(decipher, start_index + i) != *vector::borrow(&SHA256_ALGORITHM_ID, i)) {
                // Simplified debug output to avoid type conversion issues
                std::debug::print(&b"Parameter mismatch detected in ASN.1 structure");
                return false
            };
            i = i + 1;
        };

        // Extract and verify the actual message hash
        let hash_start = start_index + SHA256_ALGORITHM_ID_LEN;
        let extracted_hash = vector::empty();
        let i = 0;
        while (i < SHA256_HASH_LEN) {
            vector::push_back(&mut extracted_hash, *vector::borrow(decipher, hash_start + i));
            i = i + 1;
        };
        
        std::debug::print(&b"Extracted hash:");
        std::debug::print(&extracted_hash);
        
        true
    }

    /// Helper function to check if parameters match recursively
    fun check_params_match(decipher: &vector<u8>, d_index: u64, params: &vector<u8>, p_index: u64, len: u64): bool {
        if (p_index >= len) {
            true
        } else {
            let decipher_byte = *vector::borrow(decipher, d_index + p_index);
            let param_byte = *vector::borrow(params, p_index);
            if (decipher_byte != param_byte) {
                false
            } else {
                check_params_match(decipher, d_index, params, p_index + 1, len)
            }
        }
    }

    /// Convert bytes to u256 (represented as vector<u64> with 4 elements)
    fun bytes_to_u256(bytes: &vector<u8>): vector<u64> {
        let result = vector::empty<u64>();
        let i = 0;
        while (i < 4) {
            let val = 0u64;
            let j = 0;
            while (j < 8) {
                if (i * 8 + j < vector::length(bytes)) {
                    val = (val << 8) | (*vector::borrow(bytes, i * 8 + j) as u64);
                };
                j = j + 1;
            };
            vector::push_back(&mut result, val);
            i = i + 1;
        };
        result
    }

    /// Convert u256 (vector<u64> with 4 elements) to bytes
    fun u256_to_bytes(value: &vector<u64>): vector<u8> {
        let result = vector::empty<u8>();
        let i = 0;
        while (i < 4) {
            let val = *vector::borrow(value, i);
            let j = 7;
            while (true) {
                vector::push_back(&mut result, ((val >> (j * 8)) & 0xFF) as u8);
                if (j == 0) { break };
                j = j - 1;
            };
            i = i + 1;
        };
        result
    }

    /// Get bit at position i in u256 number
    fun get_bit(value: &vector<u64>, i: u64): bool {
        let limb_idx = i / 64;
        let bit_idx = i % 64;
        let limb = *vector::borrow(value, limb_idx);
        ((limb >> bit_idx) & 1) == 1
    }

    /// Modular multiplication for u256 numbers
    fun mod_mul_u256(a: &vector<u64>, b: &vector<u64>, m: &vector<u64>): vector<u64> {
        // Initialize result to 0
        let result = vector::empty<u64>();
        let i = 0;
        while (i < 4) {
            vector::push_back(&mut result, 0u64);
            i = i + 1;
        };

        // For each bit in b
        let i = 0;
        while (i < U256_BITS) {
            // Double result
            if (i > 0) {
                result = mod_add_u256(&result, &result, m);
            };
            
            // Add a if current bit is 1
            if (get_bit(b, i)) {
                result = mod_add_u256(&result, a, m);
            };
            
            i = i + 1;
        };

        result
    }

    /// Modular addition for u256 numbers
    fun mod_add_u256(a: &vector<u64>, b: &vector<u64>, m: &vector<u64>): vector<u64> {
        let result = vector::empty<u64>();
        let carry = 0u64;
        
        // Add corresponding limbs
        let i = 0;
        while (i < 4) {
            let sum = *vector::borrow(a, i) + *vector::borrow(b, i) + carry;
            carry = if (sum < *vector::borrow(a, i)) { 1 } else { 0 };
            vector::push_back(&mut result, sum);
            i = i + 1;
        };

        // Reduce modulo m
        while (compare_u256(&result, m) >= 0) {
            let i = 0;
            let borrow = 0u64;
            while (i < 4) {
                let diff = *vector::borrow(&result, i)
                    .wrapping_sub(*vector::borrow(m, i))
                    .wrapping_sub(borrow);
                borrow = if (diff > *vector::borrow(&result, i)) { 1 } else { 0 };
                *vector::borrow_mut(&mut result, i) = diff;
                i = i + 1;
            };
        };

        result
    }

    /// Compare two u256 numbers
    fun compare_u256(a: &vector<u64>, b: &vector<u64>): i8 {
        let i = 3;
        while (true) {
            let a_val = *vector::borrow(a, i);
            let b_val = *vector::borrow(b, i);
            if (a_val > b_val) { return 1 }
            else if (a_val < b_val) { return -1 };
            if (i == 0) { break };
            i = i - 1;
        };
        0
    }
}
