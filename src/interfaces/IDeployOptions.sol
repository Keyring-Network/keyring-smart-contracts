// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IDeployOptions {
    struct DeployOptions {
        uint256 deployerPrivateKey;
        string signatureCheckerName;
        string proxyAddress;
        address admin;
        address keyManager;
        address upgrader;
        address blacklistManager;
        address operator;
        string etherscanApiKey;
        string verifierUrl;
    }

    struct RotateKeyOptions {
        uint256 deployerPrivateKey;
        address proxyAddress;
        string previousKey;
        string key;
        uint256 validFrom;
        uint256 validUntil;
    }

    struct ManageRolesOptions {
        uint256 deployerPrivateKey;
        address proxyAddress;
        address user;
        bytes32 role;
        bool assign;
    }
}
