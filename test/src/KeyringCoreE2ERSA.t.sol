// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {BaseDeployTest} from "./../utils/BaseDeployTest.t.sol";
import {IKeyringCore} from "./../../src/interfaces/IKeyringCore.sol";

contract KeyringCoreE2ERSATest is BaseDeployTest {
    bytes public registeredKey1 =
        hex"ab067f172127a5f2611960c158f33de52ae940c7313d0c3ad95031d5a7a86142ea8f2500f4206d1c67087d4c60e0046c723f07aef45156d42f7155a461dcafb3cf3d2fa6b8cb77d8abecd834c9cf9769709414d85a5030f161e512981cf4534f3c6ea19286f08e53affa0155b5e9376efefb34a38bd8d8168bd0ba63542aa933";
    bytes public registeredKey2 =
        hex"beeaa894e810db1e941e013e644ca5c5cdebf692767ac9a8c0e7bf11f01f1acbf7771359e323457cdedf1559cd6f4675a853596203c62d800474ac9f049957d7ccf9c766dc4be3fcd1e924073fe99bcae977cc955fedabc209405a7b16bd47ed0ee5c8ce06706e474481b3e9c5ae3a0624f427078944533bb3d7a0084cfe5d95";
    bytes public unregisteredKey =
        hex"ade47ca88c8e9d3c3b157fa73b23aca81f7bc48e49f510e671a9e4610e813df5a65f8b05dbfb2a09787cf6f0d523522389bf8f315480cc5207cbde74bb47f14483dc172abcb091a2c34c18b1c38eafdf574e1fe794364edd2b81b11aa9e60a6c14d9fb75ac85b1c0a3257889d6202d92510abf5826e0bf2f226514e1fb0fb15d";
    bytes signatureMsg1 =
        hex"52646d189f3467cab366080801ad7e9903a98077ddd83a9e574d1596b0361c027b1419bf655b8b84a4a4691a5bca9cb0be012b52816d4d6411b9cbd9d9070a3dc4167f14423c7f4f508d0a1e853c75dc3ff89d8a25b890409d2b9044954bcd58dbe255380ff3443197b67580421281ba3caaf96bb555636d686180e1457a15d3";
    bytes signatureMsg2 =
        hex"43f0f4bc77973b4ba967c7668091ece7e195c05b8bf8ae2887a03d78566f063f0bbd5c9000acd7da4b8b8afaedf8d9ade489e1b80e3aaecadfb596286d12dbf13aee3cb2de2c05cf153fa065abe326b88d25565ef3d78bd6e919aff89ec450df41094462856c37f04b1a0a969b22113303b069376a35a3d042c6dfcd8695bb98";
    bytes signatureMsg3 =
        hex"0f94110eab55b5a80d0cee629982ed777ca69c86b78f11d1222c1d9329a434150df3fc4a1aee353374478b8b3bebe71c09054c2ad28cf93de4a48bb7a2ecdf261f484827f1b828f1e9e0845d4f27666ed07d850f22f49a5197b526d3b6ceaa771285f5d2fc8c11c17f13b9b55c2200851c3a429fb0abfe019a8deeb90e09287d";
    address tradingAddress = 0x0123456789abcDEF0123456789abCDef01234567;
    uint32 policyId = 123456;
    uint256 validUntil = 1627849600;
    uint256 cost = 1000000000000000000;
    bytes backdoor = hex"6578616d706c655f6261636b646f6f725f64617461";

    IKeyringCore keyringCore;

    function setUp() public override {
        super.setUp();
        vm.chainId(1625247600);
        setEnv("SIGNATURE_CHECKER_NAME", "RSASignatureChecker");
        setEnv("PRIVATE_KEY", deployerPrivateKey);
        keyringCore = run();
        vm.startPrank(keyringCore.admin());
        keyringCore.registerKey(block.timestamp, block.timestamp + 1000, registeredKey1);
        keyringCore.registerKey(block.timestamp, block.timestamp + 1000, registeredKey2);
        vm.stopPrank();
        assertEq(
            keyringCore.getKeyHash(registeredKey1), 0xe52a7c12d4c85c83f074d657813427b6d9c7ac2fef28d112045580ce15154373
        );
        assertEq(
            keyringCore.getKeyHash(registeredKey2), 0x095553bd651410e9de12ad23a85b2486138c3193e9000baef462f6d1313e4333
        );
        assertEq(
            keyringCore.getKeyHash(registeredKey2), 0x095553bd651410e9de12ad23a85b2486138c3193e9000baef462f6d1313e4333
        );
    }

    function test_createCredentialWithRegisteredKey1() public {
        assertEq(keyringCore.checkCredential(tradingAddress, policyId), false);
        keyringCore.createCredential{value: cost}(
            tradingAddress, policyId, uint256(block.chainid), validUntil, cost, registeredKey1, signatureMsg1, backdoor
        );
        assertEq(keyringCore.checkCredential(tradingAddress, policyId), true);
    }

    function test_createCredentialWithRegisteredKey2() public {
        assertEq(keyringCore.checkCredential(tradingAddress, policyId), false);
        keyringCore.createCredential{value: cost}(
            tradingAddress, policyId, uint256(block.chainid), validUntil, cost, registeredKey2, signatureMsg2, backdoor
        );
        assertEq(keyringCore.checkCredential(tradingAddress, policyId), true);
    }

    function test_createCredentialWithUnregisteredKey() public {
        assertEq(keyringCore.checkCredential(tradingAddress, policyId), false);
        vm.expectRevert(
            abi.encodeWithSelector(IKeyringCore.ErrInvalidCredential.selector, policyId, tradingAddress, "BDK")
        );
        keyringCore.createCredential{value: cost}(
            tradingAddress, policyId, uint256(block.chainid), validUntil, cost, unregisteredKey, signatureMsg3, backdoor
        );
    }
}
