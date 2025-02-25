// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

contract MessagePacker {
    /**
     * @dev Packing format of the message to be signed.
     * @param tradingAddress The trading address.
     * @param policyId The policy ID.
     * @param validUntil The expiration time of the credential.
     * @param cost The cost of the credential.
     * @param backdoor The backdoor data.
     * @return The encoded message.
     */
    function packMessage(
        address tradingAddress,
        uint256 policyId,
        uint256 validUntil,
        uint256 cost,
        bytes calldata backdoor
    ) public view returns (bytes memory) {
        return abi.encodePacked(
            tradingAddress, uint8(0), uint24(policyId), block.chainid, uint32(validUntil), uint160(cost), backdoor
        );
    }
}
