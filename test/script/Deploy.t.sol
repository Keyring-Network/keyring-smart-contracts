// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Deploy} from "../../script/Deploy.s.sol";
import {AlwaysValidSignatureChecker} from "../../src/signatureCheckers/AlwaysValidSignatureChecker.sol";
import {EIP191SignatureChecker} from "../../src/signatureCheckers/EIP191SignatureChecker.sol";
import {RSASignatureChecker} from "../../src/signatureCheckers/RSASignatureChecker.sol";
import {IKeyringCore} from "../../src/interfaces/IKeyringCore.sol";
import {IDeployOptions} from "../../src/interfaces/IDeployOptions.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

contract DeployTest is Test, IDeployOptions {
    Deploy deployer;
    string deployerPrivateKeyStr;
    DeployOptions deployOptions;
    address deployerAddress;

    function setEnv(string memory key, string memory value) internal {
        if (keccak256(bytes(key)) == keccak256(bytes("PRIVATE_KEY"))) {
            deployOptions.deployerPrivateKey = uint256(bytes32(bytes(value)));
        } else if (keccak256(bytes(key)) == keccak256(bytes("SIGNATURE_CHECKER_NAME"))) {
            deployOptions.signatureCheckerName = value;
        } else if (keccak256(bytes(key)) == keccak256(bytes("PROXY_ADDRESS"))) {
            deployOptions.proxyAddress = value;
        } else if (keccak256(bytes(key)) == keccak256(bytes("REFERENCE_CONTRACT"))) {
            deployOptions.referenceContract = value;
        }
    }

    function run() internal returns (IKeyringCore) {
        return deployer.deploy(deployOptions);
    }

    function setDeployerPrivateKey() internal {
        uint256 deployerPrivateKey = 0xA11CE;
        deployerPrivateKeyStr = vm.toString(deployerPrivateKey);
        deployerAddress = vm.addr(deployerPrivateKey);
        vm.deal(deployerAddress, 100 ether);
    }

    function setUp() public {
        deployer = new Deploy();
        setDeployerPrivateKey();
        setEnv("PRIVATE_KEY", "");
        setEnv("SIGNATURE_CHECKER_NAME", "");
        setEnv("PROXY_ADDRESS", "");
        setEnv("REFERENCE_CONTRACT", "");
    }

    function test_RevertOnMissingSignatureCheckerName() public {
        setEnv("PRIVATE_KEY", deployerPrivateKeyStr);
        vm.expectRevert("Invalid signature checker name: ");
        run();
    }

    function test_RevertOnInvalidSignatureCheckerName() public {
        setEnv("PRIVATE_KEY", deployerPrivateKeyStr);
        setEnv("SIGNATURE_CHECKER_NAME", "InvalidChecker");

        vm.expectRevert("Invalid signature checker name: InvalidChecker");
        run();
    }

    function test_DeployNewProxy() public {
        setEnv("PRIVATE_KEY", deployerPrivateKeyStr);
        setEnv("SIGNATURE_CHECKER_NAME", "AlwaysValidSignatureChecker");
        IKeyringCore proxyAddress = run();

        assertTrue(address(proxyAddress) != address(0), "Proxy address should not be null");
        assertTrue(address(proxyAddress.signatureChecker()) != address(0), "Signature checker should be set");
    }

    function test_DeployWithDifferentSignatureCheckers() public {
        setEnv("PRIVATE_KEY", deployerPrivateKeyStr);

        // Test with AlwaysValidSignatureChecker
        setEnv("SIGNATURE_CHECKER_NAME", "AlwaysValidSignatureChecker");
        IKeyringCore keyringCore1 = run();
        assertTrue(address(keyringCore1) != address(0));
        assertTrue(address(keyringCore1.signatureChecker()) != address(0));

        // Test with EIP191SignatureChecker
        setEnv("SIGNATURE_CHECKER_NAME", "EIP191SignatureChecker");
        IKeyringCore keyringCore2 = run();
        assertTrue(address(keyringCore2) != address(0));
        assertTrue(address(keyringCore2.signatureChecker()) != address(0));

        // Test with RSASignatureChecker
        setEnv("SIGNATURE_CHECKER_NAME", "RSASignatureChecker");
        IKeyringCore keyringCore3 = run();
        assertTrue(address(keyringCore3) != address(0));
        assertTrue(address(keyringCore3.signatureChecker()) != address(0));
    }

    function test_UpgradeExistingProxy() public {
        vm.skip(true, "Still having an issue with ownable");
        vm.prank(deployerAddress);
        address proxyAddress = Upgrades.deployUUPSProxy("KeyringCoreReferenceContract.sol", "");
        assertTrue(address(proxyAddress) != address(0), "Proxy address should not be null");

        setEnv("PRIVATE_KEY", deployerPrivateKeyStr);
        setEnv("SIGNATURE_CHECKER_NAME", "AlwaysValidSignatureChecker");
        setEnv("PROXY_ADDRESS", vm.toString(proxyAddress));
        setEnv("REFERENCE_CONTRACT", "KeyringCoreReferenceContract.sol");
        address upgradedProxyAddress = address(run());
        assertEq(upgradedProxyAddress, proxyAddress, "Proxy address should remain the same");
    }

    function test_RevertOnUpgradeWithInvalidOwner() public {
        uint256 maliciousPrivateKey = 0xB22DF;
        string memory maliciousAddressPrivateKeyStr = vm.toString(maliciousPrivateKey);
        address maliciousAddress = vm.addr(maliciousPrivateKey);
        vm.deal(maliciousAddress, 100 ether);
        setEnv("PRIVATE_KEY", maliciousAddressPrivateKeyStr);
        setEnv("SIGNATURE_CHECKER_NAME", "AlwaysValidSignatureChecker");
        address proxyAddress = address(run());
        assertTrue(address(proxyAddress) != address(0));

        setEnv("PROXY_ADDRESS", vm.toString(proxyAddress));
        setEnv("REFERENCE_CONTRACT", "KeyringCoreReferenceContract.sol");
        vm.expectRevert(bytes4(keccak256("InvalidInitialization()")));
        run();
    }
}
