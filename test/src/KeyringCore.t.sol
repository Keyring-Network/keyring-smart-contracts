// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {IKeyringCore} from "../../src/interfaces/IKeyringCore.sol";
import {Deploy} from "../../script/Deploy.s.sol";
import {AlwaysValidSignatureChecker} from "../../src/signatureCheckers/AlwaysValidSignatureChecker.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

contract KeyringCoreTest is Test {
    IKeyringCore public keyringCore;
    uint256 deployerPrivateKey;
    address deployerAddress;

    address public admin = address(this);
    address public newAdmin = address(0x2);
    address public feeRecipient = address(0x3);
    address public blacklistedEntity = address(0x4);
    address public user = address(0x5);
    bytes public key = "0x1234";
    uint256 public validTo = 2000;
    uint256 public policyId = 1;
    bytes public testKey = hex"abcd";
    bytes32 public testKeyHash;

    function setUp() public {
        keyringCore = IKeyringCore(
            Upgrades.deployUUPSProxy(
                "KeyringCore.sol", abi.encodeCall(IKeyringCore.initialize, address(new AlwaysValidSignatureChecker()))
            )
        );
        testKeyHash = keyringCore.getKeyHash(testKey);
    }

    function test_SetAdmin() public {
        keyringCore.setAdmin(newAdmin);
        assertEq(keyringCore.admin(), newAdmin);

        vm.prank(newAdmin);
        keyringCore.setAdmin(admin);
        assertEq(keyringCore.admin(), admin);
    }

    function test_RegisterAndRevokeKey() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, key);
        bytes32 keyHash = keccak256(key);
        assertTrue(keyringCore.keyExists(keyHash));

        keyringCore.revokeKey(keyHash);
        assertFalse(keyringCore.keyExists(keyHash));
    }

    function test_BlacklistAndUnblacklistEntity() public {
        keyringCore.blacklistEntity(policyId, blacklistedEntity);
        assertTrue(keyringCore.entityBlacklisted(policyId, blacklistedEntity));

        keyringCore.unblacklistEntity(policyId, blacklistedEntity);
        assertFalse(keyringCore.entityBlacklisted(policyId, blacklistedEntity));
    }

    function test_CollectFees() public {
        vm.deal(address(keyringCore), 1 ether);
        keyringCore.collectFees(feeRecipient);
        assertEq(feeRecipient.balance, 1 ether);
    }

    function test_FailSetAdminFromNonAdmin() public {
        vm.prank(newAdmin);
        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrCallerNotAdmin.selector, newAdmin));
        keyringCore.setAdmin(address(0x5));
    }

    function test_FailRegisterKeyFromNonAdmin() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        vm.prank(newAdmin);
        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrCallerNotAdmin.selector, newAdmin));
        keyringCore.registerKey(validFrom, validTo, key);
    }

    function test_FailRevokeKeyFromNonAdmin() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, key);
        bytes32 keyHash = keccak256(key);

        vm.prank(newAdmin);
        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrCallerNotAdmin.selector, newAdmin));
        keyringCore.revokeKey(keyHash);
    }

    function test_FailBlacklistEntityFromNonAdmin() public {
        vm.prank(newAdmin);
        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrCallerNotAdmin.selector, newAdmin));
        keyringCore.blacklistEntity(policyId, blacklistedEntity);
    }

    function test_FailUnblacklistEntityFromNonAdmin() public {
        keyringCore.blacklistEntity(policyId, blacklistedEntity);

        vm.prank(newAdmin);
        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrCallerNotAdmin.selector, newAdmin));
        keyringCore.unblacklistEntity(policyId, blacklistedEntity);
    }

    function test_FailCollectFeesFromNonAdmin() public {
        vm.deal(address(keyringCore), 1 ether);

        vm.prank(newAdmin);
        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrCallerNotAdmin.selector, newAdmin));
        keyringCore.collectFees(feeRecipient);
    }

    // Constructor and Admin Initialization Test
    function test_ConstructorInitialAdmin() public view {
        assertEq(keyringCore.admin(), admin);
    }

    // Admin Functionality Tests
    function test_SetAdminByAdmin() public {
        keyringCore.setAdmin(newAdmin);
        assertEq(keyringCore.admin(), newAdmin);
    }

    function test_SetAdminByNonAdmin() public {
        vm.prank(newAdmin);
        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrCallerNotAdmin.selector, newAdmin));
        keyringCore.setAdmin(newAdmin);
    }

    // Key Registration Tests
    function test_RegisterKeyByAdmin() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);
        assertTrue(keyringCore.keyExists(testKeyHash));
    }

    function test_RegisterKeyByNonAdmin() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        vm.prank(newAdmin);
        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrCallerNotAdmin.selector, newAdmin));
        keyringCore.registerKey(validFrom, validTo, testKey);
    }

    function test_RegisterKeyAlreadyRegistered() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);
        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrInvalidKeyRegistration.selector, "KAR"));
        keyringCore.registerKey(validFrom, validTo, testKey);
    }

    function test_RevokeKeyByAdmin() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);
        keyringCore.revokeKey(testKeyHash);
        assertFalse(keyringCore.keyExists(testKeyHash));
    }

    function test_RevokeKeyByNonAdmin() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);
        vm.prank(newAdmin);
        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrCallerNotAdmin.selector, newAdmin));
        keyringCore.revokeKey(testKeyHash);
    }

    function test_RevokeNonExistentKey() public {
        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrKeyNotFound.selector, testKeyHash));
        keyringCore.revokeKey(testKeyHash);
    }

    // Entity Blacklisting Tests
    function test_BlacklistEntityByAdmin() public {
        keyringCore.blacklistEntity(1, newAdmin);
        assertTrue(keyringCore.entityBlacklisted(1, newAdmin));
    }

    function test_BlacklistEntityByNonAdmin() public {
        vm.prank(newAdmin);
        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrCallerNotAdmin.selector, newAdmin));
        keyringCore.blacklistEntity(1, newAdmin);
    }

    function test_UnblacklistEntityByAdmin() public {
        keyringCore.blacklistEntity(1, newAdmin);
        keyringCore.unblacklistEntity(1, newAdmin);
        assertFalse(keyringCore.entityBlacklisted(1, newAdmin));
    }

    function test_UnblacklistEntityByNonAdmin() public {
        keyringCore.blacklistEntity(1, newAdmin);
        vm.prank(newAdmin);
        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrCallerNotAdmin.selector, newAdmin));
        keyringCore.unblacklistEntity(1, newAdmin);
    }

    function test_CredentialCreationExpired() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 2 days;
        keyringCore.registerKey(validFrom, validTo, testKey);

        uint256 validUntil = block.timestamp + 1 days;
        vm.warp(block.timestamp + 1 days + 1 minutes);

        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrInvalidCredential.selector, 1, newAdmin, "EXP"));
        keyringCore.createCredential{value: 1 ether}(newAdmin, 1, block.chainid, validUntil, 1 ether, testKey, "", "");
    }

    // Credential Creation Tests
    function test_CreateCredentialWithWrongChainId() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);

        uint256 validUntil = block.timestamp + 1 days;

        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrInvalidCredential.selector, 1, newAdmin, "CHAINID"));
        keyringCore.createCredential{value: 1 ether}(newAdmin, 1, 1234567890, validUntil, 1 ether, testKey, "", "");
    }

    // Credential Creation Tests
    function test_CreateCredentialOkAndKo() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);

        // pass 1 - new credential
        uint256 validUntil = block.timestamp + 1 days;
        keyringCore.createCredential{value: 1 ether}(user, 1, block.chainid, validUntil, 1 ether, testKey, "", "");
        assertTrue(keyringCore.checkCredential(1, user));

        // pass 2 - same credential, but different validUntil
        validUntil = validUntil + 32 seconds;
        keyringCore.createCredential{value: 1 ether}(newAdmin, 1, block.chainid, validUntil, 1 ether, testKey, "", "");
        assertTrue(keyringCore.checkCredential(1, user));

        // fail - same credential, yet different validUntil, but with invalid signature
        validUntil = validUntil + 32 seconds;
        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrInvalidCredential.selector, 1, user, "SIG"));
        // dead is a special signature that will never be valid for the AlwaysValidSignatureChecker
        keyringCore.createCredential{value: 1 ether}(user, 1, block.chainid, validUntil, 1 ether, hex"dead", "", "");
    }

    function test_CreateCredentialInsufficientPayment() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);

        uint256 validUntil = block.timestamp + 1 days;

        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrInvalidCredential.selector, 1, newAdmin, "VAL"));
        keyringCore.createCredential{value: 0.5 ether}(newAdmin, 1, block.chainid, validUntil, 1 ether, testKey, "", "");
    }

    function test_CreateCredentialInvalidKey() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);
        vm.warp(block.timestamp + 2 days);

        uint256 validUntil = block.timestamp + 1 days;

        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrInvalidCredential.selector, 1, newAdmin, "BDK"));
        keyringCore.createCredential{value: 1 ether}(newAdmin, 1, block.chainid, validUntil, 1 ether, testKey, "", "");
    }

    function test_CreateCredentialBlacklistedEntity() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);
        keyringCore.blacklistEntity(1, newAdmin);

        uint256 validUntil = block.timestamp + 1 days;

        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrInvalidCredential.selector, 1, newAdmin, "BLK"));
        keyringCore.createCredential{value: 1 ether}(newAdmin, 1, block.chainid, validUntil, 1 ether, testKey, "", "");
    }

    function test_CreateCredentialExpirationInPast() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);

        uint256 validUntil = block.timestamp + 1 days;

        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrInvalidCredential.selector, 1, newAdmin, "BDK"));
        vm.warp(block.timestamp + 2 days);
        keyringCore.createCredential{value: 1 ether}(newAdmin, 1, block.chainid, validUntil, 1 ether, testKey, "", "");
    }

    // Fee Collection Tests
    function test_CollectFeesByAdmin() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);

        uint256 validUntil = block.timestamp + 1 days;

        keyringCore.createCredential{value: 1 ether}(newAdmin, 1, block.chainid, validUntil, 1 ether, testKey, "", "");
        uint256 balanceBefore = address(this).balance;
        uint256 keyringBalanceBefore = address(keyringCore).balance;
        keyringCore.collectFees(admin);
        uint256 balanceAfter = address(this).balance;
        uint256 keyringBalanceAfter = address(keyringCore).balance;
        assertEq(balanceAfter, balanceBefore + 1 ether);
        assertEq(keyringBalanceAfter, keyringBalanceBefore - 1 ether);
    }

    function test_CollectFeesByNonAdmin() public {
        vm.prank(newAdmin);
        vm.expectRevert(abi.encodeWithSelector(IKeyringCore.ErrCallerNotAdmin.selector, newAdmin));
        keyringCore.collectFees(address(this));
    }

    // View Function Tests
    function test_Admin() public view {
        assertEq(keyringCore.admin(), admin);
    }

    function test_GetKeyHash() public view {
        assertEq(keyringCore.getKeyHash(testKey), testKeyHash);
    }

    function test_KeyExists() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);
        assertTrue(keyringCore.keyExists(testKeyHash));
        keyringCore.revokeKey(testKeyHash);
        assertFalse(keyringCore.keyExists(testKeyHash));
    }

    function test_KeyValidTo() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);
        assertEq(keyringCore.keyValidTo(testKeyHash), validTo);
    }

    function test_KeyDetails() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);
        IKeyringCore.KeyEntry memory kd = keyringCore.keyDetails(testKeyHash);
        assertEq(kd.validFrom, validFrom);
        assertEq(kd.validTo, validTo);
        assertTrue(kd.isValid);
    }

    function test_EntityBlacklisted() public {
        keyringCore.blacklistEntity(1, newAdmin);
        assertTrue(keyringCore.entityBlacklisted(1, newAdmin));
        keyringCore.unblacklistEntity(1, newAdmin);
        assertFalse(keyringCore.entityBlacklisted(1, newAdmin));
    }

    function test_EntityExp() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);

        uint256 validUntil = block.timestamp + 1 days;

        keyringCore.createCredential{value: 1 ether}(newAdmin, 1, block.chainid, validUntil, 1 ether, testKey, "", "");
        assertEq(keyringCore.entityExp(1, newAdmin), validUntil);
    }

    function test_EntityData() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);

        uint256 validUntil = block.timestamp + 1 days;

        keyringCore.createCredential{value: 1 ether}(newAdmin, 1, block.chainid, validUntil, 1 ether, testKey, "", "");
        IKeyringCore.EntityData memory ed = keyringCore.entityData(1, newAdmin);
        assertTrue(ed.exp == keyringCore.entityExp(1, newAdmin));
        assertTrue(ed.blacklisted == false);
    }

    function test_CheckCredential() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);

        uint256 validUntil = block.timestamp + 1 days;

        keyringCore.createCredential{value: 1 ether}(newAdmin, 1, block.chainid, validUntil, 1 ether, testKey, "", "");
        assertTrue(keyringCore.checkCredential(1, newAdmin));
    }

    function test_CheckCredentialExpired() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);

        uint256 validUntil = block.timestamp + 1 days;

        keyringCore.createCredential{value: 1 ether}(newAdmin, 1, block.chainid, validUntil, 1 ether, testKey, "", "");
        uint256 ts = block.timestamp + 2 days;
        vm.warp(ts + 1);
        assertFalse(keyringCore.checkCredential(1, newAdmin)); // Should fail due to expiration
    }

    function test_CheckCredentialBlacklisted() public {
        uint256 validFrom = block.timestamp;
        validTo = validFrom + 1 days;
        keyringCore.registerKey(validFrom, validTo, testKey);

        uint256 validUntil = block.timestamp + 1 days;

        keyringCore.createCredential{value: 1 ether}(newAdmin, 1, block.chainid, validUntil, 1 ether, testKey, "", "");
        keyringCore.blacklistEntity(1, newAdmin);
        assertFalse(keyringCore.checkCredential(1, newAdmin)); // Should fail due to blacklisting
    }

    fallback() external payable {}

    receive() external payable {}
}
