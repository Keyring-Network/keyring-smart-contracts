// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface ISignatureChecker {
    /**
     * @dev Verifies the authenticity of a message using RSA signature.
     * @param tradingAddress The trading address.
     * @param policyId The policy ID.
     * @param validUntil The expiration time of the credential.
     * @param cost The cost of the credential.
     * @param key The RSA key.
     * @param signature The signature.
     * @param backdoor The backdoor data.
     * @return True if the verification is successful, false otherwise.
     */
    function checkSignature(
        address tradingAddress,
        uint256 policyId,
        uint256 validUntil,
        uint256 cost,
        bytes calldata key,
        bytes calldata signature,
        bytes calldata backdoor
    ) external view returns (bool);
}
