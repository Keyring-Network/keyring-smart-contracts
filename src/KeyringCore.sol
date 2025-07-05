// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import "@openzeppelin-contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin-contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin-contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "./interfaces/IKeyringCore.sol";
import "./interfaces/ISignatureChecker.sol";

contract KeyringCore is IKeyringCore, Initializable, UUPSUpgradeable, AccessControlUpgradeable {
    /// @notice User's with this role can register and revoke keys.
    bytes32 public constant KEY_MANAGER_ROLE = keccak256("KEY_MANAGER_ROLE");
    /// @notice User's with this role can upgrade the contract.
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    /// @notice User's with this role can blacklist/unblacklist other users.
    bytes32 public constant BLACKLIST_MANAGER_ROLE = keccak256("BLACKLIST_MANAGER_ROLE");
    /// @notice User's with this role can withdraw any collected fees..
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @dev Current implementation version
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint64 private immutable CURRENT_VERSION;

    /// @dev Mapping from key hash to key entry.
    mapping(bytes32 => KeyEntry) internal _keys;

    /// @dev Mapping from policy ID and address to entity data.
    mapping(uint256 => mapping(address => EntityData)) internal _entityData;

    /// @dev Signature checker.
    ISignatureChecker public signatureChecker;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        CURRENT_VERSION = 4;
        _disableInitializers();
    }

    /**
     * @notice Initializes the contract.
     * @param _signatureChecker The address of the signature checker.
     * @param _admin The address that receives the default admin role.
     * @param _keyManager The address that can revoke and register keys.
     * @param _upgrader The address that is allowed to upgrade the contract.
     * @param _blacklistManager The address that can manage blacklist.
     * @param _operator The operator that is allowed to claim any collected fees.
     */
    function initialize(
        address _signatureChecker,
        address _admin,
        address _keyManager,
        address _upgrader,
        address _blacklistManager,
        address _operator
    ) public initializer {
        if (
            _admin == address(0) || _keyManager == address(0) || _upgrader == address(0)
                || _blacklistManager == address(0) || _operator == address(0)
        ) {
            revert ErrAddressZero();
        }

        __UUPSUpgradeable_init();
        __AccessControl_init();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(KEY_MANAGER_ROLE, _keyManager);
        _grantRole(UPGRADER_ROLE, _upgrader);
        _grantRole(BLACKLIST_MANAGER_ROLE, _blacklistManager);
        _grantRole(OPERATOR_ROLE, _operator);

        if (_signatureChecker == address(0)) {
            revert ErrInvalidSignatureChecker();
        }
        signatureChecker = ISignatureChecker(_signatureChecker);
    }

    /**
     * @notice Reinitializes the contract.
     * @param _signatureChecker The address of the signature checker.
     * @dev This function is only callable by the owner.
     */
    function reinitialize(address _signatureChecker)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
        reinitializer(CURRENT_VERSION)
    {
        setSignatureChecker(_signatureChecker);
    }

    /**
     * @notice Returns the initialized version of the contract.
     * @return The initialized version of the contract.
     */
    function mustBeReInitialized() public view returns (bool) {
        return _getInitializedVersion() < CURRENT_VERSION;
    }

    /**
     * @notice Authorizes the upgrade of the contract.
     * @dev This function is only callable by the owner.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}

    /**
     * @notice Sets the signature checker.
     * @param _signatureChecker The address of the signature checker.
     * @dev This function is only callable by the owner.
     */
    function setSignatureChecker(address _signatureChecker) public onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_signatureChecker == address(0)) {
            revert ErrInvalidSignatureChecker();
        }
        signatureChecker = ISignatureChecker(_signatureChecker);
    }

    /**
     * @inheritdoc IKeyringCore
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
    ) public payable override {
        // Verify the cost of the credential creation matches the value sent.
        if (msg.value != cost) {
            revert ErrInvalidCredential(policyId, tradingAddress, "VAL");
        }
        // Check for insufficient cost
        if (cost == 0) {
            revert ErrCostNotSufficient(policyId, tradingAddress, "COST");
        }
        // Check for policy ID overflow
        if (policyId > type(uint24).max) {
            revert ErrInvalidCredential(policyId, tradingAddress, "PID");
        }
        // Check for validUntil overflow
        if (validUntil > type(uint32).max) {
            revert ErrInvalidCredential(policyId, tradingAddress, "BVU");
        }
        // Check for cost overflow
        if (cost > type(uint128).max) {
            revert ErrInvalidCredential(policyId, tradingAddress, "CST");
        }
        // Check for chainId mismatch
        if (chainId != block.chainid) {
            revert ErrInvalidCredential(policyId, tradingAddress, "CHAINID");
        }
        // Verify the message
        if (!signatureChecker.checkSignature(tradingAddress, policyId, validUntil, cost, key, signature, backdoor)) {
            revert ErrInvalidCredential(policyId, tradingAddress, "SIG");
        }

        uint256 currentTime = block.timestamp;
        {
            bytes32 keyHash = getKeyHash(key);
            KeyEntry memory entry = _keys[keyHash];
            bool isValid = (entry.isValid && currentTime >= entry.validFrom && currentTime <= entry.validTo);
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

        // Update the entity data.
        _entityData[policyId][tradingAddress] = ed;
        // Emit the credential created event.
        emit CredentialCreated(policyId, tradingAddress, validUntil, backdoor);
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

    function keyChainId(bytes32) external view returns (uint256) {
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

    /**
     * @notice Registers a new RSA key.
     * @param validFrom The start time of the key's validity.
     * @param validTo The end time of the key's validity.
     * @param key The RSA key.
     * @dev Only callable by the admin.
     */
    function registerKey(uint256 validFrom, uint256 validTo, bytes memory key) external onlyRole(KEY_MANAGER_ROLE) {
        if (validTo <= validFrom) {
            revert ErrInvalidKeyRegistration("IVP");
        }
        if (validTo < block.timestamp) {
            revert ErrInvalidKeyRegistration("EXP");
        }
        bytes32 keyHash = getKeyHash(key);
        if (_keys[keyHash].isValid) {
            revert ErrInvalidKeyRegistration("KAR");
        }
        _keys[keyHash] = KeyEntry(true, uint64(validFrom), uint64(validTo));
        emit KeyRegistered(keyHash, validFrom, validTo, key);
    }

    /**
     * @notice Revokes an RSA key.
     * @param keyHash The hash of the key to revoke.
     * @dev Only callable by the admin.
     */
    function revokeKey(bytes32 keyHash) external onlyRole(KEY_MANAGER_ROLE) {
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
    function blacklistEntity(uint256 policyId, address entity_) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        if (_entityData[policyId][entity_].blacklisted == true) {
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
    function unblacklistEntity(uint256 policyId, address entity_) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        if (_entityData[policyId][entity_].blacklisted == false) {
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
    function collectFees(address to) external onlyRole(OPERATOR_ROLE) {
        sendValue(payable(to), address(this).balance);
    }

    /**
     * @notice Internal function that sends value to a recipient.
     * @param recipient The address of the recipient.
     * @param amount The amount to send.
     * @dev Throws an error if the send fails.
     */
    function sendValue(address payable recipient, uint256 amount) private {
        (bool success,) = recipient.call{value: amount}("");
        if (!success) {
            revert ErrFailedSendOfValue();
        }
    }
}
