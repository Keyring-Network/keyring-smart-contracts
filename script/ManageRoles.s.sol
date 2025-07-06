// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console, VmSafe} from "forge-std/Script.sol";
import {Strings} from "@openzeppelin-contracts/utils/Strings.sol";

import {IDeployOptions} from "../src/interfaces/IDeployOptions.sol";

import {KeyringCore} from "../src/KeyringCore.sol";

contract ManageRoles is Script, IDeployOptions {
    using Strings for string;

    function run() external {
        // ManageRolesOptions memory manageRolesOptions;
        // manageRolesOptions = ManageRolesOptions({
        //     deployerPrivateKey: vm.envUint("PRIVATE_KEY"),
        //     proxyAddress: vm.envAddress("PROXY_ADDRESS"),
        //     user: vm.envAddress("USER"),
        //     role: vm.envBytes32("ROLE"),
        //     assign: vm.envBool("ASSIGN")
        // });

        // mangeRoles(manageRolesOptions);
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address proxy = vm.envAddress("PROXY_ADDRESS");

        vm.startBroadcast(deployerPrivateKey);
        KeyringCore(proxy).grantRole(bytes32(0), 0x3eb3CD91c631dDf579723141d397d400000997cc);
        KeyringCore(proxy).grantRole(keccak256("KEY_MANAGER_ROLE"), 0x19586fbC1e0f39ED6A0400B1Db688159195611b7);
        KeyringCore(proxy).grantRole(keccak256("UPGRADER_ROLE"), 0xfa98f653b8ef3Fa786f7eB16203358Ed7D06eE5A);
        KeyringCore(proxy).grantRole(keccak256("BLACKLIST_MANAGER_ROLE"), 0xb098d68B4611D6226Ba25cdA36760CFfd3FCAc26);
        KeyringCore(proxy).grantRole(keccak256("OPERATOR_ROLE"), 0xf9A782c8463f9d02D2BE1E74dF47c6768F3De280);

        KeyringCore(proxy).revokeRole(keccak256("KEY_MANAGER_ROLE"), msg.sender);
        KeyringCore(proxy).revokeRole(keccak256("UPGRADER_ROLE"), msg.sender);
        KeyringCore(proxy).revokeRole(keccak256("BLACKLIST_MANAGER_ROLE"), msg.sender);
        KeyringCore(proxy).revokeRole(keccak256("OPERATOR_ROLE"), msg.sender);
        KeyringCore(proxy).revokeRole(bytes32(0), msg.sender);
        vm.stopBroadcast();
    }

    // function mangeRoles(ManageRolesOptions memory _manageRolesOptions) public {
    //     vm.startBroadcast(_manageRolesOptions.deployerPrivateKey);
    //     if (_manageRolesOptions.assign) {
    //         KeyringCore(_manageRolesOptions.proxyAddress).grantRole(_manageRolesOptions.role, _manageRolesOptions.user);
    //     } else {
    //         KeyringCore(_manageRolesOptions.proxyAddress).revokeRole(_manageRolesOptions.role, _manageRolesOptions.user);
    //     }
    //     vm.stopBroadcast();
    // }
}
