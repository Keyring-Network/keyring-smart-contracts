// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.22;

import "./MessagePacker.sol";
import "../interfaces/ISignatureChecker.sol";

contract AlwaysValidSignatureChecker is ISignatureChecker, MessagePacker {
    /**
     * @inheritdoc ISignatureChecker
     */
    function checkSignature(address, uint256, uint256, uint256, bytes calldata, bytes calldata, bytes calldata)
        external
        pure
        returns (bool)
    {
        return true;
    }
}
