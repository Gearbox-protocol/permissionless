// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";

struct ContractValue {
    string key;
    address value;
    uint256 version;
}

/// @title Address provider interface
interface IAddressProvider is IVersion {
    event SetAddress(string indexed key, uint256 indexed version, address indexed value);

    function owner() external view returns (address);

    function addresses(string memory key, uint256 _version) external view returns (address);

    function getAddress(bytes32 key, uint256 _version) external view returns (address);

    function getAddressOrRevert(string memory key, uint256 _version) external view returns (address);

    function getAddressOrRevert(bytes32 key, uint256 _version) external view returns (address);

    function getAllSavedContracts() external view returns (ContractValue[] memory);

    function getLatestAddressOrRevert(string memory key) external view returns (address);

    function getLatestAddressOrRevert(bytes32 _key) external view returns (address result);

    function setAddress(string memory key, address addr, bool saveVersion) external;

    function setAddress(address addr, bool saveVersion) external;
}
