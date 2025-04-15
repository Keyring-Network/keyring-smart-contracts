// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {BaseDeployTest} from "./../utils/BaseDeployTest.t.sol";
import {IKeyringCore} from "./../../src/interfaces/IKeyringCore.sol";

contract KeyringCoreE2EEIP191Test is BaseDeployTest {
    bytes public key = hex"19e7e376e7c213b7e7e7e46cc70a5dd086daff2a";
    bytes signatureMsg =
        hex"bb59932f52c7340cfcdb0004a8f0f2c201fe340047ae3bca54f430f0710e871470eb455179e0ef9367aa2c7e0c3606f3dffb65869249da04c184074984600b691c";
    bytes invalidSignatureMsg =
        hex"bb59932f52c7340cfcdb0004a8f0f2c201fe340047ae3bca54f430f0710e871470eb455179e0ef9367aa2c7e0c3606f3dffb65869249da04c184074984600b691d";
    address tradingAddress = 0x0123456789abcDEF0123456789abCDef01234567;
    uint32 policyId = 123456;
    uint256 validUntil = 1627849600;
    uint256 cost = 1000000000000000000;
    bytes backdoor = hex"6578616d706c655f6261636b646f6f725f64617461";

    IKeyringCore keyringCore;

    function setUp() public override {
        super.setUp();
        vm.chainId(1625247600);
        setEnv("SIGNATURE_CHECKER_NAME", "EIP191SignatureChecker");
        setEnv("PRIVATE_KEY", deployerPrivateKey);
        keyringCore = run();
        vm.startPrank(keyringCore.admin());
        keyringCore.registerKey(block.timestamp, block.timestamp + 1000, key);
        vm.stopPrank();
        assertEq(keyringCore.getKeyHash(key), 0x8dd832049319556c1cd22ed66ae790d07fea25830a6151c2f0a9879b3ef61305);
    }

    function test_createCredentialWithRegisteredKey() public {
        assertEq(keyringCore.checkCredential(tradingAddress, policyId), false);
        keyringCore.createCredential{value: cost}(
            tradingAddress, policyId, block.chainid, validUntil, cost, key, signatureMsg, backdoor
        );
        assertEq(keyringCore.checkCredential(tradingAddress, policyId), true);
    }

    function test_createCredentialWithInvalidMessageSignature() public {
        assertEq(keyringCore.checkCredential(tradingAddress, policyId), false);
        vm.expectRevert(
            abi.encodeWithSelector(IKeyringCore.ErrInvalidCredential.selector, policyId, tradingAddress, "SIG")
        );
        keyringCore.createCredential{value: cost}(
            tradingAddress, policyId, block.chainid, validUntil, cost, key, invalidSignatureMsg, backdoor
        );
        assertEq(keyringCore.checkCredential(tradingAddress, policyId), false);
    }

    function test_createCredentialWithUnregisteredKey() public {
        assertEq(keyringCore.checkCredential(tradingAddress, policyId), false);
        vm.startPrank(keyringCore.admin());
        keyringCore.revokeKey(keyringCore.getKeyHash(key));
        vm.stopPrank();
        vm.expectRevert(
            abi.encodeWithSelector(IKeyringCore.ErrInvalidCredential.selector, policyId, tradingAddress, "BDK")
        );
        keyringCore.createCredential{value: cost}(
            tradingAddress, policyId, block.chainid, validUntil, cost, key, signatureMsg, backdoor
        );
    }
}
