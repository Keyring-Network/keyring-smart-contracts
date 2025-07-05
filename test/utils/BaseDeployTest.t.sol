// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "../../script/Deploy.s.sol";
import {IDeployOptions} from "../../src/interfaces/IDeployOptions.sol";
import {IKeyringCore} from "../../src/interfaces/IKeyringCore.sol";

contract BaseDeployTest is IDeployOptions, Test {
    Deploy deployer;
    DeployOptions deployOptions;
    uint256 deployerPrivateKey;
    address deployerAddress;

    function setEnv(string memory key, uint256 value) internal {
        if (keccak256(bytes(key)) == keccak256(bytes("PRIVATE_KEY"))) {
            deployOptions.deployerPrivateKey = value;
        } else {
            revert("Unknown environment variable");
        }
    }

    function setEnv(string memory key, address value) internal {
        if (keccak256(bytes(key)) == keccak256(bytes("ADMIN"))) {
            deployOptions.admin = value;
        } else if (keccak256(bytes(key)) == keccak256(bytes("KEY_MANAGER"))) {
            deployOptions.keyManager = value;
        } else if (keccak256(bytes(key)) == keccak256(bytes("UPGRADER"))) {
            deployOptions.upgrader = value;
        } else if (keccak256(bytes(key)) == keccak256(bytes("BLACKLIST_MANAGER"))) {
            deployOptions.blacklistManager = value;
        } else if (keccak256(bytes(key)) == keccak256(bytes("OPERATOR"))) {
            deployOptions.operator = value;
        } else {
            revert("Unknown environment variable");
        }
    }

    function setEnv(string memory key, string memory value) internal {
        if (keccak256(bytes(key)) == keccak256(bytes("SIGNATURE_CHECKER_NAME"))) {
            deployOptions.signatureCheckerName = value;
        } else if (keccak256(bytes(key)) == keccak256(bytes("PROXY_ADDRESS"))) {
            deployOptions.proxyAddress = value;
        } else if (keccak256(bytes(key)) == keccak256(bytes("ETHERSCAN_API_KEY"))) {
            deployOptions.etherscanApiKey = value;
        } else if (keccak256(bytes(key)) == keccak256(bytes("ETHERSCAN_BASE_API_URL"))) {
            deployOptions.verifierUrl = value;
        } else {
            revert("Unknown environment variable");
        }
    }

    function run() internal returns (IKeyringCore) {
        return deployer.deploy(deployOptions);
    }

    function setUp() public virtual {
        deployer = new Deploy();
        deployerPrivateKey = 0xA11CE;
        deployerAddress = vm.addr(deployerPrivateKey);
        vm.deal(deployerAddress, 100 ether);
        setEnv("PRIVATE_KEY", 0);
        setEnv("SIGNATURE_CHECKER_NAME", "");
        setEnv("PROXY_ADDRESS", "");
        setEnv("ETHERSCAN_API_KEY", "");
        setEnv("ETHERSCAN_BASE_API_URL", "");
    }
}
