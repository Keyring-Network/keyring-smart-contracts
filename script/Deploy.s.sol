// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console, VmSafe} from "forge-std/Script.sol";
import {KeyringCore} from "../src/KeyringCore.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {Options} from "openzeppelin-foundry-upgrades/Options.sol";
import {IDeployOptions} from "../src/interfaces/IDeployOptions.sol";
import {Strings} from "@openzeppelin-contracts/utils/Strings.sol";
import {RSASignatureChecker} from "../src/signatureCheckers/RSASignatureChecker.sol";
import {EIP191SignatureChecker} from "../src/signatureCheckers/EIP191SignatureChecker.sol";
import {AlwaysValidSignatureChecker} from "../src/signatureCheckers/AlwaysValidSignatureChecker.sol";

contract Deploy is Script, IDeployOptions {
    using Strings for string;

    function run() external returns (KeyringCore) {
        DeployOptions memory deployOptions;
        string memory emptyString = "";
        deployOptions = DeployOptions({
            deployerPrivateKey: vm.envUint("PRIVATE_KEY"),
            signatureCheckerName: vm.envOr("SIGNATURE_CHECKER_NAME", emptyString),
            proxyAddress: vm.envOr("PROXY_ADDRESS", emptyString),
            admin: vm.envAddress("ADMIN"),
            keyManager: vm.envAddress("KEY_MANAGER"),
            upgrader: vm.envAddress("UPGRADER"),
            blacklistManager: vm.envAddress("BLACKLIST_MANAGER"),
            operator: vm.envAddress("OPERATOR"),
            etherscanApiKey: vm.envOr("ETHERSCAN_API_KEY", emptyString),
            verifierUrl: vm.envOr("ETHERSCAN_BASE_API_URL", emptyString)
        });
        return deploy(deployOptions);
    }

    function deploy(DeployOptions memory deployOptions) public returns (KeyringCore) {
        // Parse the proxy address
        address proxyAddress =
            bytes(deployOptions.proxyAddress).length > 0 ? vm.parseAddress(deployOptions.proxyAddress) : address(0);

        // Deploy the signature checker
        // TODO: ultra low prio find a way to not redeploy the signature checker if it already exists
        vm.startBroadcast(deployOptions.deployerPrivateKey);
        address signatureCheckerAddress;
        if (deployOptions.signatureCheckerName.equal("RSASignatureChecker")) {
            signatureCheckerAddress = address(new RSASignatureChecker());
        } else if (deployOptions.signatureCheckerName.equal("AlwaysValidSignatureChecker")) {
            signatureCheckerAddress = address(new AlwaysValidSignatureChecker());
        } else if (deployOptions.signatureCheckerName.equal("EIP191SignatureChecker")) {
            signatureCheckerAddress = address(new EIP191SignatureChecker());
        } else {
            revert(string.concat("Invalid signature checker name: ", deployOptions.signatureCheckerName));
        }
        vm.stopBroadcast();

        if (proxyAddress == address(0)) {
            // Deploy the proxy
            console.log("Deploying the KeyringCore contract proxy and implementation");
            vm.startBroadcast(deployOptions.deployerPrivateKey);
            proxyAddress = Upgrades.deployUUPSProxy(
                "KeyringCore.sol",
                abi.encodeCall(
                    KeyringCore.initialize,
                    (
                        signatureCheckerAddress,
                        deployOptions.admin,
                        deployOptions.keyManager,
                        deployOptions.upgrader,
                        deployOptions.blacklistManager,
                        deployOptions.operator
                    )
                )
            );
            KeyringCore keyringCore = KeyringCore(proxyAddress);
            if (keyringCore.mustBeReInitialized()) {
                console.log("Bump version to most recent");
                keyringCore.reinitialize(signatureCheckerAddress);
            }
            vm.stopBroadcast();
        } else {
            // Upgrade the proxy
            console.log("Upgrading the KeyringCore contract proxy");
            Options memory upgradeOptions;
            upgradeOptions.referenceContract = "KeyringCoreReferenceContract.sol";
            vm.startBroadcast(deployOptions.deployerPrivateKey);
            Upgrades.upgradeProxy(
                proxyAddress,
                "KeyringCore.sol",
                abi.encodeCall(KeyringCore.reinitialize, signatureCheckerAddress),
                upgradeOptions
            );
            vm.stopBroadcast();
        }
        // store the proxy address in the file out/KeyringCoreProxy.address only if we're not in a test context
        if (!vm.isContext(VmSafe.ForgeContext.Test)) {
            vm.writeFile("out/KeyringCoreProxy.address", vm.toString(proxyAddress));
        }
        if (KeyringCore(proxyAddress).mustBeReInitialized()) {
            revert("KeyringCore must be reinitialized");
        }
        return KeyringCore(proxyAddress);
    }
}
