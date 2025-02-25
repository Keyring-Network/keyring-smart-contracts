// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

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
     * @param chainId The chainId for which a credential is valid.
     * @param validTo The end time of the key's validity.
     */
    struct KeyEntry {
        bool isValid;
        uint64 chainId;
        uint64 validTo;
    }

    /// @notice This error is returned if the contract is already initialized. Prevents double set of admin on upgrade.
    error ErrAlreadyInitialized();

    /// @notice Error for unauthorized admin caller.
    /// @param caller The address of the unauthorized caller.
    error ErrCallerNotAdmin(address caller);

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
    /// @param chainId The chainId for which the key is valid.
    /// @param validTo The end time of the key's validity.
    /// @param publicKey The public key.
    event KeyRegistered(bytes32 indexed keyHash, uint256 indexed chainId, uint256 indexed validTo, bytes publicKey);

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

    /// @notice Event emitted when the admin is set.
    /// @param oldAdmin The address of the old admin.
    /// @param newAdmin The address of the new admin.
    event AdminSet(address indexed oldAdmin, address indexed newAdmin);

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
}
