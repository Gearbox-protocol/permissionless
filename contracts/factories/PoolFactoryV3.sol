// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {AbstractFactory} from "./AbstractFactory.sol";
import {AP_POOL, AP_POOL_QUOTA_KEEPER, AP_POOL_RATE_KEEPER, AP_DEGEN_NFT} from "../libraries/ContractLiterals.sol";
import {IMarketConfiguratorV3} from "../interfaces/IMarketConfiguratorV3.sol";
import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";
import {ACLTrait} from "@gearbox-protocol/core-v3/contracts/traits/ACLTrait.sol";

contract PoolFactoryV3 is AbstractFactory, IVersion {
    /// @notice Contract version
    uint256 public constant override version = 3_10;

    constructor(address _addressProvider) AbstractFactory(_addressProvider) {}

    function deploy(
        address underlying,
        address interestRateModel,
        uint256 totalDebtLimit,
        string calldata name,
        string calldata symbol,
        uint256 _version,
        bytes32 _salt
    ) external marketConfiguratorOnly returns (address pool) {
        address acl = ACLTrait(msg.sender).acl();

        bytes memory constructorParams = abi.encode(acl, underlying, interestRateModel, totalDebtLimit, name, symbol);

        /// @notice tries to deploy version for specific (fee) token
        try IBytecodeRepository(bytecodeRepository).deploy(
            string.concat(AP_POOL, "_", IERC20Metadata(underlying).symbol()), _version, constructorParams, _salt
        ) returns (address deployedContract) {
            return deployedContract;
        } catch {}

        return IBytecodeRepository(bytecodeRepository).deploy(AP_POOL, _version, constructorParams, _salt);
    }

    function deployPoolQuotaKeeper(address pool, uint256 _version, bytes32 _salt) external returns (address pqk) {
        bytes memory constructorParams = abi.encode(pool);
        return IBytecodeRepository(bytecodeRepository).deploy(AP_POOL_QUOTA_KEEPER, _version, constructorParams, _salt);
    }

    function deployRateKeeper(address pool, string memory rateKeeperType, uint256 _version, bytes32 _salt)
        external
        returns (address rateKeeper)
    {
        bytes memory constructorParams = abi.encode(pool);
        return IBytecodeRepository(bytecodeRepository).deploy(
            string.concat(AP_POOL_RATE_KEEPER, rateKeeperType), _version, constructorParams, _salt
        );
    }

    function deployDegenNFT(
        address acl,
        address contractRegister,
        string memory accessType,
        uint256 _version,
        bytes32 _salt
    ) external returns (address rateKeeper) {
        bytes memory constructorParams = abi.encode(acl, contractRegister);
        return IBytecodeRepository(bytecodeRepository).deploy(
            string.concat(AP_DEGEN_NFT, accessType), _version, constructorParams, _salt
        );
    }
}
