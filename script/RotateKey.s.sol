// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console, VmSafe} from "forge-std/Script.sol";
import {Strings} from "@openzeppelin-contracts/utils/Strings.sol";

import {IDeployOptions} from "../src/interfaces/IDeployOptions.sol";

import {KeyringCore} from "../src/KeyringCore.sol";

contract RotateKey is Script, IDeployOptions {
    using Strings for string;

    function run() external {
        RotateKeyOptions memory rotateKeyOptions;
        rotateKeyOptions = RotateKeyOptions({
            deployerPrivateKey: vm.envUint("PRIVATE_KEY"),
            proxyAddress: vm.envAddress("KEYRING_PROXY"),
            previousKey: vm.envString("PREVIOUS_KEY"),
            key: vm.envString("KEY"),
            validFrom: vm.envUint("VALID_FROM"),
            validUntil: vm.envUint("VALID_UNTIL")
        });

        rotateKey(rotateKeyOptions);
    }

    function rotateKey(RotateKeyOptions memory _rotateKeyOptions) public {
        bytes memory previousKey =
            bytes(_rotateKeyOptions.previousKey).length > 0 ? vm.parseBytes(_rotateKeyOptions.previousKey) : bytes("");
        bytes memory key = vm.parseBytes(_rotateKeyOptions.key);

        vm.startBroadcast(_rotateKeyOptions.deployerPrivateKey);
        if (previousKey.length > 0) KeyringCore(_rotateKeyOptions.proxyAddress).revokeKey(keccak256(previousKey));
        KeyringCore(_rotateKeyOptions.proxyAddress).registerKey(
            _rotateKeyOptions.validFrom, _rotateKeyOptions.validUntil, key
        );
        vm.stopBroadcast();
    }
}
