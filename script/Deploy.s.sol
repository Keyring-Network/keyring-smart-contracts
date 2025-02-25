// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console, VmSafe} from "forge-std/Script.sol";
import {KeyringCore} from "../src/KeyringCore.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {Options} from "openzeppelin-foundry-upgrades/Options.sol";
import {Strings} from "@openzeppelin-contracts/utils/Strings.sol";
import {RSASignatureChecker} from "../src/messageVerifiers/RSASignatureChecker.sol";
import {EIP191SignatureChecker} from "../src/messageVerifiers/EIP191SignatureChecker.sol";
import {AlwaysValidSignatureChecker} from "../src/messageVerifiers/AlwaysValidSignatureChecker.sol";

contract Deploy is Script {
    using Strings for string;

    string constant ADDRESSES_DIR = "addresses/";

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        string memory networkName = vm.envString("NETWORK_NAME");
        string memory filePath = string.concat(ADDRESSES_DIR, networkName, ".txt");

        if (!vm.exists(filePath)) {
            console.log("No proxy address file found for network", networkName);

            vm.startBroadcast(deployerPrivateKey);

            console.log("Deploying the Signature Checker", vm.envString("SIGNATURE_CHECKER_NAME"));
            address signatureCheckerAddress;
            string memory signatureCheckerName = vm.envString("SIGNATURE_CHECKER_NAME");
            if (signatureCheckerName.equal("RSASignatureChecker")) {
                signatureCheckerAddress = address(new RSASignatureChecker());
            } else if (signatureCheckerName.equal("EIP191SignatureChecker")) {
                signatureCheckerAddress = address(new EIP191SignatureChecker());
            } else if (signatureCheckerName.equal("AlwaysValidSignatureChecker")) {
                signatureCheckerAddress = address(new AlwaysValidSignatureChecker());
            } else {
                revert("Invalid signature checker name");
            }

            console.log("Deploying the KeyringCore contract proxy and implementation");
            address proxyAddress = Upgrades.deployUUPSProxy(
                "KeyringCore.sol", abi.encodeCall(KeyringCore.initialize, signatureCheckerAddress)
            );
            vm.stopBroadcast();
            if (vm.isContext(VmSafe.ForgeContext.ScriptBroadcast)) {
                console.log("Deployment is actually broadcasted, saving the proxy address to the file");
                vm.writeFile(filePath, Strings.toHexString(uint256(uint160(proxyAddress)), 20));
            } else {
                console.log(
                    "Deployment is not broadcasted, skipping the file saving (add --broadcast to the command to save the address)"
                );
            }
        } else {
            console.log("Proxy address file found for network", networkName);

            address proxyAddress = vm.parseAddress(vm.readFile(filePath));
            console.log("Upgrading the KeyringCore contract for the proxy at", proxyAddress);
            vm.startBroadcast(deployerPrivateKey);
            Upgrades.upgradeProxy(proxyAddress, "KeyringCore.sol", abi.encodeCall(KeyringCore.reinitialize, ()));
            vm.stopBroadcast();
        }
    }
}
