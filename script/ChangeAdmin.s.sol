// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console, VmSafe} from "forge-std/Script.sol";
import {Strings} from "@openzeppelin-contracts/utils/Strings.sol";

import {IDeployOptions} from "../src/interfaces/IDeployOptions.sol";

import {KeyringCore} from "../src/KeyringCore.sol";

contract ChangeAdmin is Script, IDeployOptions {
    using Strings for string;

    function run() external {
        ChangeAdmin memory changeAdminOptions;
        changeAdminOptions = ChangeAdmin({
            deployerPrivateKey: vm.envUint("PRIVATE_KEY"),
            proxyAddress: vm.envAddress("PROXY_ADDRESS"),
            newAdmin: vm.envAddress("NEW_ADMIN")
        });

        changeAdmin(changeAdminOptions);
    }

    function changeAdmin(ChangeAdmin memory _changeAdminOptions) public {
        vm.startBroadcast(_changeAdminOptions.deployerPrivateKey);
        KeyringCore(_changeAdminOptions.proxyAddress).transferOwnership(_changeAdminOptions.newAdmin);
        vm.stopBroadcast();
    }
}
