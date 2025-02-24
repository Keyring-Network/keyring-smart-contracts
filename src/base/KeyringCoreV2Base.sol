// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "../lib/RsaMessagePacking.sol";
import "../interfaces/ICoreV2Base.sol";
/**
 * @title KeyringCoreV2 Contract
 * @dev This contract manages policy states, credentials, and whitelisting/blacklisting of entities.
 */
abstract contract KeyringCoreV2Base is ICoreV2Base, RsaMessagePacking {

    /// @dev Address of the admin.
    address internal _admin;

    /// @dev Mapping from key hash to key entry.
    mapping(bytes32 => KeyEntry) internal _keys;

    /// @dev Mapping from policy ID and address to entity data.
    mapping(uint256 => mapping(address => EntityData)) internal _entityData;

    /**
     * @dev Initializes the contract setting the deployer as the initial admin.
     * @dev This function is called only once during the contract deployment.
     * @dev This should NOT be called after the initial upgrade to avoid double initialization.
     */
    function _initialize() internal {
        if (_admin != address(0)) {
            return;
        }
        _admin = msg.sender;
        emit AdminSet(address(0), msg.sender);
    }

    // VIEW FUNCTIONS

    /**
     * @notice Returns the address of the admin.
     * @return The address of the admin.
     */
    function admin() external view returns (address) {
        return _admin;
    }

    /**
     * @notice Returns the hash of a key.
     * @param key The key.
     * @return The hash of the key.
     */
    function getKeyHash(bytes memory key) public pure returns (bytes32) {
        return keccak256(key);
    }

    /**
     * @notice Checks if a key exists.
     * @param keyHash The hash of the key.
     * @return True if the key exists, false otherwise.
     */
    function keyExists(bytes32 keyHash) external view returns (bool) {
        return _keys[keyHash].isValid;
    }

    function keyChainId(bytes32 keyHash) external view returns (uint256) {
        return block.chainid;
    }

    /**
     * @notice Returns the validity end time of a key.
     * @param keyHash The hash of the key.
     * @return The end time of the key's validity.
     */
    function keyValidTo(bytes32 keyHash) external view returns (uint256) {
        return _keys[keyHash].validTo;
    }

    /**
     * @notice Returns the details of a key.
     * @param keyHash The hash of the key.
     * @return The KeyEntry struct containing key details.
     */
    function keyDetails(bytes32 keyHash) external view returns (KeyEntry memory) {
        return _keys[keyHash];
    }

    /**
     * @notice Checks if an entity is blacklisted for a specific policy.
     * @param policyId The ID of the policy.
     * @param entity_ The address of the entity.
     * @return True if the entity is blacklisted, false otherwise.
     */
    function entityBlacklisted(uint256 policyId, address entity_) external view returns (bool) {
        return _entityData[policyId][entity_].blacklisted;
    }

    /**
     * @notice Returns the expiration of an entity for a specific policy.
     * @param policyId The ID of the policy.
     * @param entity_ The address of the entity.
     * @return The expiration of the entity credential.
     */
    function entityExp(uint256 policyId, address entity_) external view returns (uint256) {
        return _entityData[policyId][entity_].exp;
    }

    /**
     * @notice Returns the data associated with a specific entity.
     * @param policyId The ID of the policy.
     * @param entity_ The address of the entity.
     * @return The EntityData struct containing blacklisting and expiration information.
     */
    function entityData(uint256 policyId, address entity_) external view returns (EntityData memory) {
        return _entityData[policyId][entity_];
    }

    /**
     * @notice Checks if an entity has a valid credential.
     * @param policyId The ID of the policy.
     * @param entity_ The address of the entity to check.
     * @return True if the entity has a valid credential, false otherwise.
     */
    function checkCredential(uint256 policyId, address entity_) public view returns (bool) {
        EntityData memory ed = _entityData[policyId][entity_];
        if (!ed.blacklisted && ed.exp > block.timestamp) {
            return true;
        }
        return false;
    }

    /**
     * @notice Checks if two entities have valid credentials.
     * @param policyId The ID of the policy.
     * @param entityA_ The address of the first entity.
     * @param entityB_ The address of the second entity.
     * @return True if both entities have valid credentials, false otherwise.
     */
    function checkCredential(uint256 policyId, address entityA_, address entityB_) external view returns (bool) {
        return checkCredential(policyId, entityA_) && checkCredential(policyId, entityB_);
    }

    /**
     * @notice Checks if an entity has a valid credential and supports legacy interface.
     * @param policyId The ID of the policy.
     * @param entity_ The address of the entity to check.
     * @return True if the entity has a valid credential, false otherwise.
     */
    function checkCredential(address entity_, uint32 policyId) external view returns (bool) {
        return checkCredential(policyId, entity_);
    }

    // CREDENTIAL CREATION
    /**
     * @notice Creates a credential for an entity.
     * @param tradingAddress The trading address.
     * @param policyId The policy ID.
     * @param chainId The chainId for which a credential is valid.
     * @param validUntil The expiration time of the credential.
     * @param cost The cost of the credential.
     * @param key The RSA key.
     * @param signature The signature.
     * @param backdoor The backdoor data.
     */
    function createCredential(
        address tradingAddress,
        uint256 policyId,
        uint256 chainId,
        uint256 validUntil,
        uint256 cost,
        bytes calldata key,
        bytes calldata signature,
        bytes calldata backdoor
    ) external virtual payable {

        if (chainId != block.chainid) {
            revert ErrInvalidCredential(policyId, tradingAddress, "CHAINID");
        }
        _createCredential(tradingAddress, policyId, validUntil, cost, key, backdoor);
    }

    // ADMIN CAPABILITIES

    /**
     * @notice Sets a new admin.
     * @param newAdmin The address of the new admin.
     * @dev Only callable by the current admin.
     */
    function setAdmin(address newAdmin) external {
        if (msg.sender != _admin) {
            revert ErrCallerNotAdmin(msg.sender);
        }
        _admin = newAdmin;
        emit AdminSet(msg.sender, newAdmin);
    }

    /**
     * @notice Registers a new RSA key.
     * @param chainId The chainId for which a credential is valid.
     * @param validTo The end time of the key's validity.
     * @param key The RSA key.
     * @dev Only callable by the admin.
     */
    function registerKey(uint256 chainId, uint256 validTo, bytes memory key) external {
        if (msg.sender != _admin) {
            revert ErrCallerNotAdmin(msg.sender);
        }
        if (chainId != block.chainid) {
            // convert chainId to string
            //string memory chainIdStr = Strings.toString(block.chainid);
            revert ErrInvalidKeyRegistration("CHAINID");
        }
        if (validTo < block.timestamp) {
            revert ErrInvalidKeyRegistration("EXP");
        }
        bytes32 keyHash = getKeyHash(key);
        if (_keys[keyHash].isValid) {
            revert ErrInvalidKeyRegistration("KAR");
        }
        _keys[keyHash] = KeyEntry(true, uint64(chainId), uint64(validTo));
        emit KeyRegistered(keyHash, chainId, validTo, key);
    }

    /**
     * @notice Revokes an RSA key.
     * @param keyHash The hash of the key to revoke.
     * @dev Only callable by the admin.
     */
    function revokeKey(bytes32 keyHash) external {
        if (msg.sender != _admin) {
            revert ErrCallerNotAdmin(msg.sender);
        }
        if (!_keys[keyHash].isValid) {
            revert ErrKeyNotFound(keyHash);
        }

        _keys[keyHash].isValid = false;
        emit KeyRevoked(keyHash);
    }

    /**
     * @notice Blacklists an entity.
     * @param policyId The ID of the policy.
     * @param entity_ The address of the entity to blacklist.
     * @dev Only callable by the admin.
     */
    function blacklistEntity(uint256 policyId, address entity_) external {
        if (msg.sender != _admin) {
            revert ErrCallerNotAdmin(msg.sender);
        }
        if(_entityData[policyId][entity_].blacklisted == true) {
            return;
        }
        EntityData memory ed = EntityData(true, 0);
        _entityData[policyId][entity_] = ed;
        emit EntityBlacklisted(policyId, entity_);
    }

    /**
     * @notice Removes an entity from the blacklist.
     * @param policyId The ID of the policy.
     * @param entity_ The address of the entity to unblacklist.
     * @dev Only callable by the admin.
     */
    function unblacklistEntity(uint256 policyId, address entity_) external {
        if (msg.sender != _admin) {
            revert ErrCallerNotAdmin(msg.sender);
        }
        if(_entityData[policyId][entity_].blacklisted == false) {
            return;
        }
        EntityData memory ed = EntityData(false, 0);
        _entityData[policyId][entity_] = ed;
        emit EntityUnblacklisted(policyId, entity_);
    }

    /**
    * @notice Collects fees and transfers them to the specified address.
    * @param to The address to transfer the collected fees to.
    * @dev Only callable by the admin.
    * @custom:requires msg.sender must be the admin.
    * @custom:emits This function does not emit any events.
    * @custom:throws ErrCallerNotAdmin if the caller is not the admin.
    */
    function collectFees(address to) external {
        if (msg.sender != _admin) {
            revert ErrCallerNotAdmin(msg.sender);
        }
        sendValue(payable(to), address(this).balance);
    }


    // INTERNAL FUNCTIONS

    /**
     * @notice Internal function that creates a credential for an entity.
     * @param tradingAddress The trading address.
     * @param policyId The policy ID.
     * @param validUntil The expiration time of the credential.
     * @param cost The cost of the credential.
     * @param key The RSA key.
     * @param backdoor The backdoor data.
     */
    function _createCredential(
        address tradingAddress,
        uint256 policyId,
        uint256 validUntil,
        uint256 cost,
        bytes calldata key,
        bytes calldata backdoor) internal {
        // Verify the cost of the credential creation matches the value sent.
        if (msg.value != cost) {
            revert ErrInvalidCredential(policyId, tradingAddress, "VAL");
        }

        // Check for insufficient cost
        if (cost == 0) {
            revert ErrCostNotSufficient(policyId, tradingAddress, "COST");
        }
   
        // Verify the key is valid.
        uint256 currentTime = block.timestamp;
        {
            bytes32 keyHash = getKeyHash(key);
            KeyEntry memory entry = _keys[keyHash];
            bool isValid = (entry.isValid && block.chainid == entry.chainId && currentTime <= entry.validTo);
            // Verify the key is valid.
            if (!isValid) {
                revert ErrInvalidCredential(policyId, tradingAddress, "BDK");
            }
        }
        // Calculate the expiration for the credential.
        if (validUntil < currentTime) {
            revert ErrInvalidCredential(policyId, tradingAddress, "EXP");
        }
        // Load the entity data.
        EntityData memory ed = _entityData[policyId][tradingAddress];
        // Check if the entity is blacklisted.
        if (ed.blacklisted) {
            revert ErrInvalidCredential(policyId, tradingAddress, "BLK");
        }
        if (validUntil <= ed.exp) {
            revert ErrInvalidCredential(policyId, tradingAddress, "STL");
        }
        // Set the expiration for the entity.
        ed.exp = uint64(validUntil);
        _entityData[policyId][tradingAddress] = ed;
        // Update the entity data.
        // Emit the credential created event.
        emit CredentialCreated(policyId, tradingAddress, validUntil, backdoor);
    }

    /** 
    * @notice Internal function that sends value to a recipient.
    * @param recipient The address of the recipient.
    * @param amount The amount to send.
    * @dev Throws an error if the send fails.
    */
    function sendValue(address payable recipient, uint256 amount) private {
        (bool success, ) = recipient.call{value: amount}("");
        if (!success) {
            revert ErrFailedSendOfValue();
        }
    }

}
