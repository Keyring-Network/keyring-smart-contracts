// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ISignatureChecker} from "./ISignatureChecker.sol";

/**
 * @title IKeyringCore
 * @notice Interface for the KeyringCore contract. This acts as a definition point for structs, events, and errors.
 */
interface IKeyringCore {
    /**
     * @notice Represents data associated with an entity.
     * @dev Contains whitelisting status and expiration information.
     * @param blacklisted Indicates if the entity is blacklisted.
     * @param exp The expiration for the entity's credential.
     */
    struct EntityData {
        bool blacklisted;
        uint64 exp;
    }

    /**
     * @notice Represents a key entry.
     * @dev Contains validity status and the validity period of the key.
     * @param isValid Indicates if the key is valid.
     * @param validFrom The start time of the key's validity.
     * @param validTo The end time of the key's validity.
     */
    struct KeyEntry {
        bool isValid;
        uint64 validFrom;
        uint64 validTo;
    }

    /// @notice This error is thrown when the input address is a zero address.
    error ErrAddressZero();

    /// @notice This error is returned if the signature checker is invalid.
    error ErrInvalidSignatureChecker();

    /// @notice This error is returned if the contract is already initialized. Prevents double set of admin on upgrade.
    error ErrAlreadyInitialized();

    /// @notice Error for invalid key registration.
    /// @param reason The reason for the invalid key registration.
    error ErrInvalidKeyRegistration(string reason);

    /// @notice Error for key not found.
    /// @param keyHash The hash of the key that was not found.
    error ErrKeyNotFound(bytes32 keyHash);

    /// @notice Error for failed send of value.
    error ErrFailedSendOfValue();

    /// @notice Error for expired credential.
    /// @param policyId The ID of the policy.
    /// @param entity The address of the entity.
    /// @param reason The reason for the invalid credential.
    error ErrInvalidCredential(uint256 policyId, address entity, string reason);

    /// @notice Error for insufficient cost (calldata.cost is zero msg.value < cost).
    /// @param policyId The ID of the policy.
    /// @param entity The address of the entity.
    /// @param reason The reason for the insufficient cost.
    error ErrCostNotSufficient(uint256 policyId, address entity, string reason);

    /// @notice Error for policy overflows.
    error PolicyOverflows();

    /// @notice Event emitted when a key is registered.
    /// @param keyHash The hash of the key.
    /// @param validFrom The start time of the key's validity.
    /// @param validTo The end time of the key's validity.
    /// @param publicKey The public key.
    event KeyRegistered(bytes32 indexed keyHash, uint256 indexed validFrom, uint256 indexed validTo, bytes publicKey);

    /// @notice Event emitted when a key is revoked.
    /// @param keyHash The hash of the key.
    event KeyRevoked(bytes32 indexed keyHash);

    /// @notice Event emitted when a credential is created.
    /// @param policyId The ID of the policy.
    /// @param entity The address of the entity.
    /// @param exp The expiration for the credential.
    /// @param backdoor The backdoor data.
    event CredentialCreated(uint256 indexed policyId, address indexed entity, uint256 indexed exp, bytes backdoor);

    /// @notice Event emitted when a credential is revoked.
    /// @param policyId The ID of the policy.
    /// @param entity The address of the entity.
    event CredentialRevoked(uint256 indexed policyId, address indexed entity);

    /// @notice Event emitted when an entity is blacklisted.
    /// @param policyId The ID of the policy.
    /// @param entity The address of the entity.
    event EntityBlacklisted(uint256 indexed policyId, address indexed entity);

    /// @notice Event emitted when an entity is unblacklisted.
    /// @param policyId The ID of the policy.
    /// @param entity The address of the entity.
    event EntityUnblacklisted(uint256 indexed policyId, address indexed entity);

    function KEY_MANAGER_ROLE() external view returns (bytes32);

    function UPGRADER_ROLE() external view returns (bytes32);

    function BLACKLIST_MANAGER_ROLE() external view returns (bytes32);

    function OPERATOR_ROLE() external view returns (bytes32);

    function initialize(
        address _signatureChecker,
        address _admin,
        address _keyManager,
        address _upgrader,
        address _blacklistManager,
        address _operator
    ) external;

    /**
     * @notice Creates a credential for an entity.
     * @dev This function overrides the base implementation to include RSA signature verification.
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
    ) external payable;

    /**
     * @notice Registers a key.
     * @param chainId The chainId for which the key is valid.
     * @param validTo The end time of the key's validity.
     * @param key The key.
     */
    function registerKey(uint256 chainId, uint256 validTo, bytes calldata key) external;

    /**
     * @notice Revokes a key.
     * @param keyHash The hash of the key.
     */
    function revokeKey(bytes32 keyHash) external;

    /**
     * @notice Blacklists an entity.
     * @param policyId The ID of the policy.
     * @param entity The address of the entity.
     */
    function blacklistEntity(uint256 policyId, address entity) external;

    /**
     * @notice Unblacklists an entity.
     * @param policyId The ID of the policy.
     * @param entity The address of the entity.
     */
    function unblacklistEntity(uint256 policyId, address entity) external;

    /// @notice Checks if a credential is valid for an entity.
    /// @param entity_ The address of the entity.
    /// @param policyId_ The ID of the policy.
    /// @return True if the credential is valid, false otherwise.
    function checkCredential(address entity_, uint32 policyId_) external view returns (bool);

    /// @notice Checks if a credential is valid for an entity.
    /// @param policyId_ The ID of the policy.
    /// @param entity_ The address of the entity.
    /// @return True if the credential is valid, false otherwise.
    function checkCredential(uint256 policyId_, address entity_) external view returns (bool);

    /**
     * @notice Returns if a key exists.
     * @param keyHash The hash of the key.
     * @return True if the key exists, false otherwise.
     */
    function keyExists(bytes32 keyHash) external view returns (bool);

    /**
     * @notice Returns if an entity is blacklisted.
     * @param policyId The ID of the policy.
     * @param entity The address of the entity.
     * @return True if the entity is blacklisted, false otherwise.
     */
    function entityBlacklisted(uint256 policyId, address entity) external view returns (bool);

    /**
     * @notice Returns the entity data.
     * @param policyId The ID of the policy.
     * @param entity The address of the entity.
     * @return The entity data.
     */
    function entityData(uint256 policyId, address entity) external view returns (EntityData memory);

    /**
     * @notice Collects the fees.
     * @param recipient The address of the recipient.
     */
    function collectFees(address recipient) external;

    /**
     * @notice Returns the signature checker.
     * @return The signature checker.
     */
    function signatureChecker() external view returns (ISignatureChecker);

    /**
     * @notice Returns the hash of a key.
     * @param key The key.
     * @return The hash of the key.
     */
    function getKeyHash(bytes calldata key) external pure returns (bytes32);

    /**
     * @notice Returns the validTo of a key.
     * @param keyHash The hash of the key.
     * @return The validTo of the key.
     */
    function keyValidTo(bytes32 keyHash) external view returns (uint256);

    /**
     * @notice Returns the key details.
     * @param keyHash The hash of the key.
     * @return The key details.
     */
    function keyDetails(bytes32 keyHash) external view returns (KeyEntry memory);

    /**
     * @notice Returns the expiration of an entity.
     * @param policyId The ID of the policy.
     * @param entity The address of the entity.
     * @return The expiration of the entity.
     */
    function entityExp(uint256 policyId, address entity) external view returns (uint256);
}
