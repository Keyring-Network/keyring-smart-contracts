// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console, VmSafe} from "forge-std/Script.sol";
import {Strings} from "@openzeppelin-contracts/utils/Strings.sol";

import {IDeployOptions} from "../src/interfaces/IDeployOptions.sol";

import {KeyringCore} from "../src/KeyringCore.sol";

contract ManageRoles is Script, IDeployOptions {
    using Strings for string;

    function run() external {
        ManageRolesOptions memory manageRolesOptions;
        manageRolesOptions = ManageRolesOptions({
            deployerPrivateKey: vm.envUint("PRIVATE_KEY"),
            proxyAddress: vm.envAddress("PROXY_ADDRESS"),
            user: vm.envAddress("USER"),
            role: vm.envBytes32("ROLE"),
            assign: vm.envBool("ASSIGN")
        });

        mangeRoles(manageRolesOptions);
    }

    function mangeRoles(ManageRolesOptions memory _manageRolesOptions) public {
        vm.startBroadcast(_manageRolesOptions.deployerPrivateKey);
        if (_manageRolesOptions.assign) {
            KeyringCore(_manageRolesOptions.proxyAddress).grantRole(_manageRolesOptions.role, _manageRolesOptions.user);
        } else {
            KeyringCore(_manageRolesOptions.proxyAddress).revokeRole(_manageRolesOptions.role, _manageRolesOptions.user);
        }
        vm.stopBroadcast();
    }
}
