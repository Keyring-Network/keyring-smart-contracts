// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Deploy} from "../../script/Deploy.s.sol";
import {AlwaysValidSignatureChecker} from "../../src/signatureCheckers/AlwaysValidSignatureChecker.sol";
import {EIP191SignatureChecker} from "../../src/signatureCheckers/EIP191SignatureChecker.sol";
import {RSASignatureChecker} from "../../src/signatureCheckers/RSASignatureChecker.sol";
import {IKeyringCore} from "../../src/interfaces/IKeyringCore.sol";
import {IDeployOptions} from "../../src/interfaces/IDeployOptions.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {KeyringCoreReferenceContract} from "../../src/referenceContract/KeyringCoreReferenceContract.sol";
import {BaseDeployTest} from "../utils/BaseDeployTest.t.sol";

contract DeployTest is BaseDeployTest {
    function test_RevertOnMissingSignatureCheckerName() public {
        setEnv("PRIVATE_KEY", deployerPrivateKey);
        setEnv("ADMIN", deployerAddress);
        setEnv("KEY_MANAGER", deployerAddress);
        setEnv("UPGRADER", deployerAddress);
        setEnv("BLACKLIST_MANAGER", deployerAddress);
        setEnv("OPERATOR", deployerAddress);
        vm.expectRevert("Invalid signature checker name: ");
        run();
    }

    function test_RevertOnInvalidSignatureCheckerName() public {
        setEnv("PRIVATE_KEY", deployerPrivateKey);
        setEnv("SIGNATURE_CHECKER_NAME", "InvalidChecker");
        setEnv("ADMIN", deployerAddress);
        setEnv("KEY_MANAGER", deployerAddress);
        setEnv("UPGRADER", deployerAddress);
        setEnv("BLACKLIST_MANAGER", deployerAddress);
        setEnv("OPERATOR", deployerAddress);

        vm.expectRevert("Invalid signature checker name: InvalidChecker");
        run();
    }

    function test_DeployNewProxy() public {
        setEnv("PRIVATE_KEY", deployerPrivateKey);
        setEnv("SIGNATURE_CHECKER_NAME", "AlwaysValidSignatureChecker");
        setEnv("ADMIN", deployerAddress);
        setEnv("KEY_MANAGER", deployerAddress);
        setEnv("UPGRADER", deployerAddress);
        setEnv("BLACKLIST_MANAGER", deployerAddress);
        setEnv("OPERATOR", deployerAddress);
        IKeyringCore proxyAddress = run();

        assertTrue(address(proxyAddress) != address(0), "Proxy address should not be null");
        assertTrue(address(proxyAddress.signatureChecker()) != address(0), "Signature checker should be set");
    }

    function test_DeployWithDifferentSignatureCheckers() public {
        setEnv("PRIVATE_KEY", deployerPrivateKey);
        setEnv("ADMIN", deployerAddress);
        setEnv("KEY_MANAGER", deployerAddress);
        setEnv("UPGRADER", deployerAddress);
        setEnv("BLACKLIST_MANAGER", deployerAddress);
        setEnv("OPERATOR", deployerAddress);

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
        vm.startPrank(deployerAddress);
        address proxyAddress = Upgrades.deployUUPSProxy(
            "KeyringCoreReferenceContract.sol",
            abi.encodeCall(KeyringCoreReferenceContract.initialize, (deployerAddress, deployerAddress))
        );
        vm.stopPrank();
        assertTrue(address(proxyAddress) != address(0), "Proxy address should not be null");
        bytes memory data = abi.encodeWithSignature("hasRole(bytes32,address)", bytes32(0x0), deployerAddress);
        (bool success, bytes memory result) = proxyAddress.staticcall(data);
        require(success, "Call failed");
        bool isAdmin = abi.decode(result, (bool));
        assertTrue(isAdmin, "Not Owner");

        setEnv("PRIVATE_KEY", deployerPrivateKey);
        setEnv("SIGNATURE_CHECKER_NAME", "AlwaysValidSignatureChecker");
        setEnv("PROXY_ADDRESS", vm.toString(proxyAddress));

        address upgradedProxyAddress = address(run());
        assertEq(upgradedProxyAddress, proxyAddress, "Proxy address should remain the same");
    }

    function test_RevertOnUpgradeWithTheSameVersion() public {
        setEnv("PRIVATE_KEY", deployerPrivateKey);
        setEnv("SIGNATURE_CHECKER_NAME", "AlwaysValidSignatureChecker");
        setEnv("ADMIN", deployerAddress);
        setEnv("KEY_MANAGER", deployerAddress);
        setEnv("UPGRADER", deployerAddress);
        setEnv("BLACKLIST_MANAGER", deployerAddress);
        setEnv("OPERATOR", deployerAddress);
        address proxyAddress = address(run());
        assertTrue(address(proxyAddress) != address(0));

        setEnv("PROXY_ADDRESS", vm.toString(proxyAddress));
        vm.expectRevert(abi.encodeWithSignature("InvalidInitialization()"));
        run();
    }

    function test_RevertOnUpgradeWithInvalidOwner() public {
        setEnv("PRIVATE_KEY", deployerPrivateKey);
        setEnv("SIGNATURE_CHECKER_NAME", "AlwaysValidSignatureChecker");
        setEnv("ADMIN", deployerAddress);
        setEnv("KEY_MANAGER", deployerAddress);
        setEnv("UPGRADER", deployerAddress);
        setEnv("BLACKLIST_MANAGER", deployerAddress);
        setEnv("OPERATOR", deployerAddress);
        address proxyAddress = address(run());
        assertTrue(address(proxyAddress) != address(0));
        bytes memory data = abi.encodeWithSignature("hasRole(bytes32,address)", bytes32(0x0), deployerAddress);
        (bool success, bytes memory result) = proxyAddress.staticcall(data);
        require(success, "Call failed");
        bool isAdmin = abi.decode(result, (bool));
        assertTrue(isAdmin, "Not Owner");

        uint256 maliciousPrivateKey = 0xB22DF;
        address maliciousAddress = vm.addr(maliciousPrivateKey);
        vm.deal(maliciousAddress, 100 ether);

        setEnv("PROXY_ADDRESS", vm.toString(proxyAddress));
        setEnv("PRIVATE_KEY", maliciousPrivateKey);
        vm.expectRevert(
            abi.encodeWithSelector(
                bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)")),
                maliciousAddress,
                keccak256("UPGRADER_ROLE")
            )
        );
        run();
    }
}
