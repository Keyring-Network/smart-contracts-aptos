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

    /// Get bit at position in word
    fun get_bit(word: u64, pos: u8): bool {
        ((word >> pos) & 1) == 1
    }

    /// Process bits for modular exponentiation using optimized fixed-window method
    fun process_exp_bits(
        exp_limbs: &vector<u64>,
        result: vector<u64>,
        base_mont: &vector<u64>,
        mod_limbs: &vector<u64>,
        n0_inv: u64
    ): vector<u64> {
        let current_result = result;
        let exp_len = vector::length(exp_limbs);
        
        // Precompute base powers for 4-bit window
        let powers = vector::empty<vector<u64>>();
        let base_copy = vector::empty<u64>();
        let i = 0;
        let len = vector::length(base_mont);
        while (i < len) {
            let element = *vector::borrow(base_mont, i);
            vector::push_back(&mut base_copy, element);
            i = i + 1;
        };
        vector::push_back(&mut powers, base_copy);  // base^1
        let i = 1;
        while (i < 16) {
            let prev = vector::borrow(&powers, i - 1);
            let next = montgomery_multiply(prev, base_mont, mod_limbs, n0_inv);
            vector::push_back(&mut powers, next);
            i = i + 1;
        };
        
        // Process 4 bits at a time from most significant to least
        let limb_idx = exp_len;
        while (limb_idx > 0) {
            limb_idx = limb_idx - 1;
            let exp_word = *vector::borrow(exp_limbs, limb_idx);
            let bit_pos = 60;  // Process 4 bits at a time
            
            // Process each 4-bit window in the current word
            let mut_pos = bit_pos;
            while (mut_pos >= 0 && mut_pos <= 60) {
                // Square 4 times
                let j = 0;
                while (j < 4) {
                    current_result = montgomery_multiply(&current_result, &current_result, mod_limbs, n0_inv);
                    j = j + 1;
                };
                
                // Extract 4-bit window
                let window = ((exp_word >> mut_pos) & 0xF) as u64;
                if (window != 0) {
                    let power = vector::borrow(&powers, (window - 1) as u64);
                    current_result = montgomery_multiply(&current_result, power, mod_limbs, n0_inv);
                };
                
                if (mut_pos == 0) { break };
                mut_pos = mut_pos - 4;
            };
        };
        
        current_result
    }

    /// Helper function to perform modular exponentiation
    /// This replaces the precompiled contract call in Solidity
    /// Uses Montgomery multiplication for efficient modular arithmetic
    fun mod_exp(
        base: vector<u8>,
        exponent: vector<u8>,
        modulus: vector<u8>
    ): vector<u8> {
        // Convert inputs to u64 limbs for efficient arithmetic
        let base_limbs = bytes_to_limbs(&base);
        let exp_limbs = bytes_to_limbs(&exponent);
        let mod_limbs = bytes_to_limbs(&modulus);
        
        // Compute Montgomery parameters
        let r_squared = compute_r_squared(&mod_limbs);
        let n0_inv = compute_n0_inv(&mod_limbs);
        
        // Convert base to Montgomery form
        let base_mont = montgomery_multiply(&base_limbs, &r_squared, &mod_limbs, n0_inv);
        
        // Initialize result to 1 in Montgomery form (which is R mod N)
        let result = r_squared;
        
        // Process each word of the exponent
        let i = 0;
        let exp_len = vector::length(&exp_limbs);
        while (i < exp_len) {
            result = process_exp_bits(&exp_limbs, result, &base_mont, &mod_limbs, n0_inv);
            i = i + 1;
        };
        
        // Convert back from Montgomery form
        let one = vector::empty();
        vector::push_back(&mut one, 1u64);
        while (vector::length(&one) < vector::length(&mod_limbs)) {
            vector::push_back(&mut one, 0u64);
        };
        result = montgomery_multiply(&result, &one, &mod_limbs, n0_inv);
        
        // Convert result back to bytes
        limbs_to_bytes(&result)
    }
    
    /// Convert bytes to u64 limbs
    fun bytes_to_limbs(bytes: &vector<u8>): vector<u64> {
        let result = vector::empty<u64>();
        let i = 0;
        let current_limb = 0u64;
        let shift = 0u8;
        
        while (i < vector::length(bytes)) {
            current_limb = current_limb | ((*vector::borrow(bytes, i) as u64) << shift);
            shift = shift + 8;
            
            if (shift == 64 || i == vector::length(bytes) - 1) {
                vector::push_back(&mut result, current_limb);
                current_limb = 0;
                shift = 0;
            };
            i = i + 1;
        };
        
        if (vector::is_empty(&result)) {
            vector::push_back(&mut result, 0);
        };
        
        result
    }
    
    /// Convert u64 limbs back to bytes
    fun limbs_to_bytes(limbs: &vector<u64>): vector<u8> {
        let result = vector::empty<u8>();
        let i = 0;
        
        while (i < vector::length(limbs)) {
            let limb = *vector::borrow(limbs, i);
            let j = 0;
            
            while (j < 8) {
                vector::push_back(&mut result, ((limb >> (j * 8)) & 0xFF) as u8);
                j = j + 1;
            };
            i = i + 1;
        };
        
        // Trim leading zeros
        while (vector::length(&result) > 1 && *vector::borrow(&result, vector::length(&result) - 1) == 0) {
            vector::pop_back(&mut result);
        };
        
        result
    }
    
    /// Compute Montgomery parameter R^2 mod N
    fun compute_r_squared(n: &vector<u64>): vector<u64> {
        let len = vector::length(n);
        let result = vector::empty<u64>();
        let i = 0;
        
        // Initialize with 2^(2*k) where k is the number of bits in modulus
        while (i < len * 2) {
            vector::push_back(&mut result, 0);
            i = i + 1;
        };
        *vector::borrow_mut(&mut result, len * 2 - 1) = 1;
        
        // Reduce modulo n
        while (compare_limbs(&result, n) >= 0) {
            subtract_limbs(&mut result, n);
        };
        
        result
    }
    
    /// Compute -n[0]^(-1) mod 2^64 for Montgomery multiplication
    fun compute_n0_inv(n: &vector<u64>): u64 {
        let n0 = *vector::borrow(n, 0);
        let y = 1u64;
        let i = 0;
        
        // Use Newton iteration to find inverse
        while (i < 6) {  // 6 iterations is enough for 64 bits
            y = y * (2 - (n0 * y));
            i = i + 1;
        };
        
        if (y == 0) { 0u64 } else { 0xFFFFFFFFFFFFFFFFu64 - y + 1 }
    }
    
    /// Convert a number to Montgomery form
    fun to_montgomery_form(
        a: &vector<u64>,
        r_squared: &vector<u64>,
        n: &vector<u64>,
        n0_inv: u64
    ): vector<u64> {
        montgomery_multiply(a, r_squared, n, n0_inv)
    }
    
    /// Perform Montgomery multiplication with optimized reduction
    fun montgomery_multiply(
        a: &vector<u64>,
        b: &vector<u64>,
        n: &vector<u64>,
        n0_inv: u64
    ): vector<u64> {
        let len = vector::length(n);
        let t = vector::empty<u64>();
        
        // Pre-allocate result vector
        let i = 0;
        while (i < len + 1) {
            vector::push_back(&mut t, 0);
            i = i + 1;
        };
        
        // Process one word at a time
        let i = 0;
        while (i < len) {
            let a_i = *vector::borrow(a, i);
            let carry = 0u64;
            
            // Optimized multiply-accumulate loop
            let j = 0;
            while (j < len) {
                let b_j = *vector::borrow(b, j);
                let t_j = *vector::borrow(&t, j);
                
                // Combined multiply-add with single carry propagation
                let (hi, lo) = mul_u64(a_i, b_j);
                let sum = ((lo as u128) + (t_j as u128) + (carry as u128));
                *vector::borrow_mut(&mut t, j) = (sum & ((1u128 << 64) - 1)) as u64;
                carry = hi + ((sum >> 64) as u64);
                j = j + 1;
            };
            
            // Add final carry
            *vector::borrow_mut(&mut t, len) = carry;
            
            // Optimized reduction step
            let m = (*vector::borrow(&t, 0) * n0_inv) & ((1u64 << 64) - 1);
            let borrow = 0u64;
            
            // Combined multiply-subtract loop
            let j = 0;
            while (j < len) {
                let n_j = *vector::borrow(n, j);
                let t_j = *vector::borrow(&t, j);
                
                let (hi, lo) = mul_u64(m, n_j);
                let sub = ((t_j as u128) - (lo as u128) - (borrow as u128));
                *vector::borrow_mut(&mut t, j) = (sub & ((1u128 << 64) - 1)) as u64;
                borrow = hi + ((sub >> 127) as u64);  // Use sign bit for borrow
                j = j + 1;
            };
            
            // Single pass shift with carry propagation
            let shift_i = 0;
            while (shift_i < len) {
                let val = *vector::borrow(&t, shift_i + 1);
                *vector::borrow_mut(&mut t, shift_i) = val;
                shift_i = shift_i + 1;
            };
            *vector::borrow_mut(&mut t, len) = 0;
            
            i = i + 1;
        };
        
        // Final reduction
        if (compare_limbs(&t, n) >= 0) {
            subtract_limbs(&mut t, n);
        };
        
        t
    }
    
    /// Subtract with borrow
    fun sub_u64_with_borrow(a: u64, b: u64, borrow: u64): (u64, bool) {
        let diff = a - b - borrow;
        (diff, diff > a || (borrow > 0 && diff == a))
    }
    
    /// Multiply two u64 values, returning (low, high) parts
    fun mul_u64(a: u64, b: u64): (u64, u64) {
        let product = (a as u128) * (b as u128);
        ((product & ((1u128 << 64) - 1)) as u64, (product >> 64) as u64)
    }
    
    /// Add two u64 values, returning sum and carry
    fun add_u64(a: u64, b: u64): (u64, bool) {
        let sum = a + b;
        (sum, sum < a)
    }
    
    /// Compare two limb vectors
    fun compare_limbs(a: &vector<u64>, b: &vector<u64>): u8 {
        let len_a = vector::length(a);
        let len_b = vector::length(b);
        
        if (len_a > len_b) {
            1
        } else if (len_a < len_b) {
            2  // represents -1
        } else {
            let i = len_a;
            while (i > 0) {
                i = i - 1;
                let a_i = *vector::borrow(a, i);
                let b_i = *vector::borrow(b, i);
                if (a_i > b_i) {
                    return 1
                } else if (a_i < b_i) {
                    return 2  // represents -1
                };
            };
            0
        }
    }
    
    /// Subtract limb vector b from a with proper overflow handling
    fun subtract_limbs(a: &mut vector<u64>, b: &vector<u64>) {
        let borrow = 0u64;
        let i = 0;
        let len = vector::length(a);
        
        while (i < len) {
            let a_i = *vector::borrow(a, i);
            let b_i = if (i < vector::length(b)) { *vector::borrow(b, i) } else { 0 };
            
            // Handle borrow from previous subtraction
            let temp = if (borrow == 1) {
                if (a_i > 0) {
                    a_i - 1
                } else {
                    0xFFFFFFFFFFFFFFFF
                }
            } else {
                a_i
            };
            
            // Perform subtraction with borrow propagation
            let (result, new_borrow) = if (temp >= b_i) {
                (temp - b_i, if (borrow == 1 && a_i == 0) { 1 } else { 0 })
            } else {
                ((0xFFFFFFFFFFFFFFFF - b_i + 1 + temp), 1)
            };
            
            *vector::borrow_mut(a, i) = result;
            borrow = new_borrow;
            i = i + 1;
        };
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


}
