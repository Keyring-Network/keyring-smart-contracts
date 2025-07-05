// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console, VmSafe} from "forge-std/Script.sol";
import {Strings} from "@openzeppelin-contracts/utils/Strings.sol";

import {IDeployOptions} from "../src/interfaces/IDeployOptions.sol";

import {KeyringCore} from "../src/KeyringCore.sol";

contract GrantRole is Script, IDeployOptions {
    using Strings for string;

    function run() external {
        GrantRoleOptions memory grantRoleOptions;
        grantRoleOptions = GrantRoleOptions({
            deployerPrivateKey: vm.envUint("PRIVATE_KEY"),
            proxyAddress: vm.envAddress("PROXY_ADDRESS"),
            user: vm.envAddress("USER"),
            role: vm.envBytes32("ROLE")
        });

        grantRole(grantRoleOptions);
    }

    function grantRole(GrantRoleOptions memory _grantRoleOptions) public {
        vm.startBroadcast(_grantRoleOptions.deployerPrivateKey);
        KeyringCore(_grantRoleOptions.proxyAddress).grantRole(_grantRoleOptions.role, _grantRoleOptions.user);
        vm.stopBroadcast();
    }
}
