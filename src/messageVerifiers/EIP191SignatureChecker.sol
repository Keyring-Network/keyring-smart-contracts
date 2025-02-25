// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.22;

import "./MessagePacker.sol";
import "../interfaces/ISignatureChecker.sol";

contract EIP191SignatureChecker is ISignatureChecker, MessagePacker {
    /**
     * @inheritdoc ISignatureChecker
     */
    function checkSignature(
        address tradingAddress,
        uint256 policyId,
        uint256 validUntil,
        uint256 cost,
        bytes calldata key,
        bytes calldata signature,
        bytes calldata backdoor
    ) external view returns (bool) {
        bytes memory message = packMessage(tradingAddress, policyId, validUntil, cost, backdoor);
        return verifySignature(message, signature, key);
    }

    /**
     * @dev Returns the keccak256 digest of an ERC-191 signed data with version
     * `0x45` (`personal_sign` messages).
     *
     * The digest is calculated by prefixing a bytes32 `messageHash` with
     * `"\x19Ethereum Signed Message:\n32"` and hashing the result. It corresponds with the
     * hash signed when using the https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_sign[`eth_sign`] JSON-RPC method.
     *
     * NOTE: The `messageHash` parameter is intended to be the result of hashing a raw message with
     * keccak256, although any bytes32 value can be safely used because the final digest will
     * be re-hashed.
     *
     * See {ECDSA-recover}.
     */
    function toEthSignedMessageHash(bytes32 messageHash) internal pure returns (bytes32 digest) {
        assembly ("memory-safe") {
            mstore(0x00, "\x19Ethereum Signed Message:\n32") // 32 is the bytes-length of messageHash
            mstore(0x1c, messageHash) // 0x1c (28) is the length of the prefix
            digest := keccak256(0x00, 0x3c) // 0x3c is the length of the prefix (0x1c) + messageHash (0x20)
        }
    }

    /**
     * @dev Verifies an EIP-191 signature
     * @param signerBytes The address of the signer as a bytes array
     * @param message The original message
     * @param signature The signature to verify
     * @return True if the signature is valid, false otherwise
     */
    function verifySignature(bytes memory message, bytes memory signature, bytes memory signerBytes)
        public
        pure
        returns (bool)
    {
        // Validate and parse the signer address
        address signer = parseAddress(signerBytes);

        // Hash the encoded message
        bytes32 messageHash = keccak256(message);

        bytes32 digest = toEthSignedMessageHash(messageHash);

        // Split the signature into r, s, and v values
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);

        // Recover the signer address from the signature
        address recoveredSigner = ecrecover(digest, v, r, s);

        // Check if the recovered signer matches the expected signer
        return recoveredSigner == signer;
    }

    /**
     * @dev Parses a signer address from a bytes array with validation
     * @param signerBytes The address as a bytes array
     * @return The address parsed from the bytes array
     */
    function parseAddress(bytes memory signerBytes) internal pure returns (address) {
        require(signerBytes.length == 20, "Invalid signer address length");

        address signer;
        assembly {
            signer := mload(add(signerBytes, 20))
        }
        return signer;
    }

    /**
     * @dev Splits a signature into its r, s, and v components
     * @param signature The signature bytes
     * @return r The r value
     * @return s The s value
     * @return v The recovery id (v value)
     */
    function splitSignature(bytes memory signature) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(signature.length == 65, "Invalid signature length");

        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        // Adjust v to be compatible with ecrecover
        if (v < 27) {
            v += 27;
        }
    }
}
