module keyring::core_v2 {
    #[test_only]
    friend keyring::core_v2_tests;
    #[test_only]
    friend keyring::rsa_verify_tests;
    use std::error;
    use std::signer;
    use std::bcs;
    use aptos_framework::timestamp;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::event::{Self, EventHandle};
    use aptos_framework::account;
    use aptos_framework::hash;
    use aptos_framework::table::{Self, Table};
    use keyring::rsa_verify::{Self, RsaKey};
    use keyring::rsa_message_packing;

    /// Module version for upgrades
    const VERSION: u64 = 1;

    /// Events
    struct KeyRegisteredEvent has drop, store {
        key_hash: vector<u8>,
        valid_from: u64,
        valid_to: u64,
        public_key: vector<u8>
    }

    struct KeyRevokedEvent has drop, store {
        key_hash: vector<u8>
    }

    struct CredentialCreatedEvent has drop, store {
        policy_id: u64,
        entity: address,
        exp: u64,
        backdoor: vector<u8>
    }

    struct EntityBlacklistedEvent has drop, store {
        policy_id: u64,
        entity: address
    }

    struct EntityUnblacklistedEvent has drop, store {
        policy_id: u64,
        entity: address
    }

    struct AdminSetEvent has drop, store {
        old_admin: address,
        new_admin: address
    }

    struct UpgradeEvent has drop, store {
        old_version: u64,
        new_version: u64,
        metadata: vector<u8>
    }

    /// Event handles stored in AdminCap
    struct EventStore has key {
        key_registered_events: EventHandle<KeyRegisteredEvent>,
        key_revoked_events: EventHandle<KeyRevokedEvent>,
        credential_created_events: EventHandle<CredentialCreatedEvent>,
        entity_blacklisted_events: EventHandle<EntityBlacklistedEvent>,
        entity_unblacklisted_events: EventHandle<EntityUnblacklistedEvent>,
        admin_set_events: EventHandle<AdminSetEvent>,
        upgrade_events: EventHandle<UpgradeEvent>
    }

    /// Error codes
    const EINVALID_SIGNER: u64 = 1;
    const EINVALID_CREDENTIAL: u64 = 2;
    const EINVALID_TIMESTAMP: u64 = 3;
    const EINVALID_ENTITY: u64 = 4;
    const EBLACKLISTED: u64 = 5;
    const EINVALID_KEY: u64 = 6;
    const EINVALID_KEY_REGISTRATION: u64 = 7;
    const EINVALID_UPGRADE: u64 = 8;

    /// Check if an address has admin capability
    public fun has_admin_cap(addr: address): bool {
        exists<AdminCap>(addr)
    }

    /// Check if a key is valid
    public fun is_key_valid(addr: address): bool acquires KeyEntry {
        if (!exists<KeyEntry>(addr)) {
            return false
        };
        let key_entry = borrow_global<KeyEntry>(addr);
        key_entry.is_valid
    }

    /// Calculate key hash using SHA3-256 (closest to Solidity's keccak256)
    fun get_key_hash(key: &vector<u8>): vector<u8> {
        hash::sha3_256(*key)
    }

    // Event structs are defined above

    /// Resource structs
    struct KeyEntry has key, store {
        is_valid: bool,
        valid_from: u64,
        valid_to: u64,
        key: RsaKey
    }

    struct EntityData has key, store {
        blacklisted: bool,
        exp: u64
    }

    struct AdminCap has key, store {
        version: u64
    }

    /// Maps trading addresses to their resource accounts
    struct ResourceAccountMap has key {
        addresses: Table<address, address>
    }

    #[test_only]
    /// Initialize module for testing
    public fun init_for_test(admin: &signer) {
        // Create admin capability with initial version and resource account map
        move_to(admin, AdminCap {
            version: VERSION
        });
        move_to(admin, ResourceAccountMap {
            addresses: table::new()
        });
        // Initialize event store
        move_to(admin, EventStore {
            key_registered_events: account::new_event_handle<KeyRegisteredEvent>(admin),
            key_revoked_events: account::new_event_handle<KeyRevokedEvent>(admin),
            credential_created_events: account::new_event_handle<CredentialCreatedEvent>(admin),
            entity_blacklisted_events: account::new_event_handle<EntityBlacklistedEvent>(admin),
            entity_unblacklisted_events: account::new_event_handle<EntityUnblacklistedEvent>(admin),
            admin_set_events: account::new_event_handle<AdminSetEvent>(admin),
            upgrade_events: account::new_event_handle<UpgradeEvent>(admin)
        });
    }

    /// Initialize module
    fun init_module(admin: &signer) acquires EventStore {
        // Create admin capability with initial version and resource account map
        move_to(admin, AdminCap {
            version: VERSION
        });
        move_to(admin, ResourceAccountMap {
            addresses: table::new()
        });
        // Initialize event store
        move_to(admin, EventStore {
            key_registered_events: account::new_event_handle<KeyRegisteredEvent>(admin),
            key_revoked_events: account::new_event_handle<KeyRevokedEvent>(admin),
            credential_created_events: account::new_event_handle<CredentialCreatedEvent>(admin),
            entity_blacklisted_events: account::new_event_handle<EntityBlacklistedEvent>(admin),
            entity_unblacklisted_events: account::new_event_handle<EntityUnblacklistedEvent>(admin),
            admin_set_events: account::new_event_handle<AdminSetEvent>(admin),
            upgrade_events: account::new_event_handle<UpgradeEvent>(admin)
        });
        // Emit initial admin set event
        let admin_addr = signer::address_of(admin);
        let events = borrow_global_mut<EventStore>(admin_addr);
        event::emit_event(&mut events.admin_set_events, AdminSetEvent {
            old_admin: @0x0,
            new_admin: admin_addr
        });
    }

    /// Create a new credential
    public entry fun create_credential(
        admin: &signer,
        trading_address: address,
        policy_id: u64,
        valid_from: u64,
        valid_until: u64,
        cost: u128,
        _key: vector<u8>,
        signature: vector<u8>,
        backdoor: vector<u8>
    ) acquires EventStore, ResourceAccountMap {
        // Verify admin capability
        assert!(exists<AdminCap>(signer::address_of(admin)), error::permission_denied(EINVALID_SIGNER));

        // Create RSA key with standard exponent
        let rsa_key = rsa_verify::create_key(x"010001", _key);

        // Pack and verify message
        let message = rsa_message_packing::pack_auth_message(
            trading_address,
            policy_id,
            valid_from,
            valid_until,
            cost,
            backdoor
        );

        // Verify signature
        assert!(
            rsa_verify::verify_auth_message(message, signature, rsa_key),
            error::invalid_argument(EINVALID_CREDENTIAL)
        );

        // Create key entry
        let key_entry = KeyEntry {
            is_valid: true,
            valid_from,
            valid_to: valid_until,
            key: rsa_key
        };

        // Create resource account for storing key entry
        let seed = bcs::to_bytes(&trading_address);
        let (resource_signer, _cap) = account::create_resource_account(admin, seed);
        let resource_addr = signer::address_of(&resource_signer);
        
        // Store mapping of trading address to resource account
        let map = borrow_global_mut<ResourceAccountMap>(signer::address_of(admin));
        table::add(&mut map.addresses, trading_address, resource_addr);
        
        // Ensure resource account doesn't already have a key entry
        assert!(!exists<KeyEntry>(resource_addr), error::already_exists(EINVALID_KEY));
        
        // Store key entry at resource account address
        move_to(&resource_signer, key_entry);

        // Emit credential created event
        let admin_addr = signer::address_of(admin);
        let events = borrow_global_mut<EventStore>(admin_addr);
        event::emit_event(&mut events.credential_created_events, CredentialCreatedEvent {
            policy_id,
            entity: trading_address,
            exp: valid_until,
            backdoor
        });
    }

    /// Check if a credential is valid
    public fun check_credential(
        trading_address: address,
        policy_id: u64,
        timestamp: u64,
        cost: u128,
        _key: vector<u8>,
        signature: vector<u8>,
        backdoor: vector<u8>
    ): bool acquires KeyEntry, EntityData, ResourceAccountMap {
        // Check if entity is blacklisted
        if (exists<EntityData>(trading_address)) {
            let entity_data = borrow_global<EntityData>(trading_address);
            if (entity_data.blacklisted) {
                return false
            };
        };

        // Get admin address from module
        let admin_addr = signer::address_of(admin);
        
        // Get resource account address from map
        if (!exists<ResourceAccountMap>(admin_addr)) {
            return false
        };
        let map = borrow_global<ResourceAccountMap>(admin_addr);
        if (!table::contains(&map.addresses, trading_address)) {
            return false
        };
        let resource_addr = *table::borrow(&map.addresses, trading_address);

        // Check if key entry exists at resource account
        if (!exists<KeyEntry>(resource_addr)) {
            return false
        };

        // Get key entry
        let key_entry = borrow_global<KeyEntry>(resource_addr);
        if (!key_entry.is_valid) {
            return false
        };

        // Check timestamp validity
        if (timestamp < key_entry.valid_from || timestamp > key_entry.valid_to) {
            return false
        };

        // Pack message
        let message = rsa_message_packing::pack_auth_message(
            trading_address,
            policy_id,
            key_entry.valid_from,
            key_entry.valid_to,
            cost,
            backdoor
        );

        // Verify signature
        rsa_verify::verify_auth_message(message, signature, key_entry.key)
    }

    /// Blacklist an entity
    public entry fun blacklist_entity(
        admin: &signer,
        policy_id: u64,
        entity: address,
        blacklisted: bool
    ) acquires EntityData, EventStore {
        // Verify admin capability
        assert!(exists<AdminCap>(signer::address_of(admin)), error::permission_denied(EINVALID_SIGNER));

        // Create or update entity data
        if (exists<EntityData>(entity)) {
            let entity_data = borrow_global_mut<EntityData>(entity);
            entity_data.blacklisted = blacklisted;
        } else {
            let entity_data = EntityData {
                blacklisted,
                exp: timestamp::now_seconds()
            };
            // Create resource account for storing entity data
            let seed = bcs::to_bytes(&entity);
            let (resource_signer, _cap) = account::create_resource_account(admin, seed);
            
            // Store entity data at resource account address
            move_to(&resource_signer, entity_data);

            // Emit appropriate event
            let admin_addr = signer::address_of(admin);
            let events = borrow_global_mut<EventStore>(admin_addr);
            if (blacklisted) {
                event::emit_event(&mut events.entity_blacklisted_events, EntityBlacklistedEvent {
                    entity,
                    policy_id
                });
            } else {
                event::emit_event(&mut events.entity_unblacklisted_events, EntityUnblacklistedEvent {
                    entity,
                    policy_id
                });
            };
        };
    }

    /// Revoke a key
    public entry fun revoke_key(
        admin: &signer,
        trading_address: address
    ) acquires KeyEntry, EventStore, ResourceAccountMap {
        // Verify admin capability
        assert!(exists<AdminCap>(signer::address_of(admin)), error::permission_denied(EINVALID_SIGNER));

        // Get admin address and verify map exists
        let admin_addr = signer::address_of(admin);
        assert!(exists<ResourceAccountMap>(admin_addr), error::not_found(EINVALID_KEY));
        
        // Get resource account address from map
        let map = borrow_global<ResourceAccountMap>(admin_addr);
        assert!(table::contains(&map.addresses, trading_address), error::not_found(EINVALID_KEY));
        let resource_addr = *table::borrow(&map.addresses, trading_address);

        // Check if key entry exists
        assert!(exists<KeyEntry>(resource_addr), error::not_found(EINVALID_KEY));

        // Revoke key
        let key_entry = borrow_global_mut<KeyEntry>(resource_addr);
        key_entry.is_valid = false;

        // Emit key revoked event
        let admin_addr = signer::address_of(admin);
        let events = borrow_global_mut<EventStore>(admin_addr);
        event::emit_event(&mut events.key_revoked_events, KeyRevokedEvent {
            key_hash: get_key_hash(&rsa_verify::get_modulus(&key_entry.key))
        });
    }

    /// Register a new RSA key
    public entry fun register_key(
        admin: &signer,
        valid_from: u64,
        valid_to: u64,
        key: vector<u8>
    ) acquires EventStore, ResourceAccountMap {
        // Verify admin capability
        assert!(exists<AdminCap>(signer::address_of(admin)), error::permission_denied(EINVALID_SIGNER));

        // Validate timestamps
        assert!(valid_to > valid_from, error::invalid_argument(EINVALID_KEY_REGISTRATION));
        assert!(valid_to > timestamp::now_seconds(), error::invalid_argument(EINVALID_KEY_REGISTRATION));

        // Create key entry
        let key_entry = KeyEntry {
            is_valid: true,
            valid_from,
            valid_to,
            key: rsa_verify::create_key(x"010001", key)
        };

        // Create resource account for storing key entry
        let admin_addr = signer::address_of(admin);
        let seed = bcs::to_bytes(&admin_addr);
        let (resource_signer, _cap) = account::create_resource_account(admin, seed);
        let resource_addr = signer::address_of(&resource_signer);
        
        // Store key entry at resource account address
        move_to(&resource_signer, key_entry);
        
        // Store mapping in ResourceAccountMap
        let map = borrow_global_mut<ResourceAccountMap>(admin_addr);
        table::add(&mut map.addresses, signer::address_of(&resource_signer), resource_addr);

        // Emit key registered event
        let admin_addr = signer::address_of(admin);
        let events = borrow_global_mut<EventStore>(admin_addr);
        event::emit_event(&mut events.key_registered_events, KeyRegisteredEvent {
            key_hash: get_key_hash(&key),
            valid_from,
            valid_to,
            public_key: key
        });
    }

    /// Collect fees and transfer them to the specified address
    public entry fun collect_fees(
        admin: &signer,
        to: address,
        amount: u64
    ) {
        // Verify admin capability
        assert!(exists<AdminCap>(signer::address_of(admin)), error::permission_denied(EINVALID_SIGNER));

        // Transfer APT coins
        coin::transfer<AptosCoin>(admin, to, amount);
    }

    /// Upgrade the module
    public entry fun upgrade(
        admin: &signer,
        metadata: vector<u8>
    ) acquires EventStore, AdminCap {
        // Verify admin capability
        let admin_addr = signer::address_of(admin);
        assert!(exists<AdminCap>(admin_addr), error::permission_denied(EINVALID_SIGNER));

        // Get current version
        let admin_cap = borrow_global_mut<AdminCap>(admin_addr);
        let current_version = admin_cap.version;

        // Verify upgrade version is newer
        let new_version = VERSION;
        assert!(new_version > current_version, error::invalid_argument(EINVALID_UPGRADE));

        // Perform upgrade and track versions for event
        let old_version = current_version;
        admin_cap.version = new_version;

        // Emit upgrade event
        let events = borrow_global_mut<EventStore>(admin_addr);
        event::emit_event(&mut events.upgrade_events, UpgradeEvent {
            old_version,
            new_version,
            metadata
        });
    }
}
