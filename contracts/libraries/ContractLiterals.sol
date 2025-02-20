// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

uint256 constant NO_VERSION_CONTROL = 0;

bytes32 constant AP_ACL = "ACL";
bytes32 constant AP_CONTRACTS_REGISTER = "CONTRACTS_REGISTER";
bytes32 constant AP_GOVERNOR = "GOVERNOR";
bytes32 constant AP_TREASURY_SPLITTER = "TREASURY_SPLITTER";

bytes32 constant AP_ADDRESS_PROVIDER = "ADDRESS_PROVIDER";
bytes32 constant AP_CROSS_CHAIN_GOVERNANCE = "CROSS_CHAIN_GOVERNANCE";
bytes32 constant AP_CROSS_CHAIN_MULTISIG = "CROSS_CHAIN_MULTISIG";
bytes32 constant AP_INSTANCE_MANAGER = "INSTANCE_MANAGER";

// PROXIES
bytes32 constant AP_INSTANCE_MANAGER_PROXY = "INSTANCE_MANAGER_PROXY";
bytes32 constant AP_TREASURY_PROXY = "TREASURY_PROXY";
bytes32 constant AP_CROSS_CHAIN_GOVERNANCE_PROXY = "CROSS_CHAIN_GOVERNANCE_PROXY";

bytes32 constant AP_POOL = "POOL";
bytes32 constant AP_POOL_QUOTA_KEEPER = "POOL_QUOTA_KEEPER";
bytes32 constant AP_INTEREST_RATE_MODEL_LINEAR = "IRM::LINEAR";
bytes32 constant AP_INTEREST_RATE_MODEL_DEFAULT = "IRM::DEFAULT";
bytes32 constant AP_RATE_KEEPER_TUMBLER = "RATE_KEEPER::TUMBLER";
bytes32 constant AP_RATE_KEEPER_GAUGE = "RATE_KEEPER::GAUGE";
bytes32 constant AP_LOSS_POLICY_DEFAULT = "LOSS_POLICY::DEFAULT";
bytes32 constant AP_ACCOUNT_FACTORY_DEFAULT = "ACCOUNT_FACTORY::DEFAULT";
bytes32 constant AP_ZERO_PRICE_FEED = "PRICE_FEED::ZERO";

bytes32 constant AP_CREDIT_MANAGER = "CREDIT_MANAGER";
bytes32 constant AP_CREDIT_FACADE = "CREDIT_FACADE";
bytes32 constant AP_CREDIT_CONFIGURATOR = "CREDIT_CONFIGURATOR";

bytes32 constant AP_PRICE_ORACLE = "PRICE_ORACLE";

bytes32 constant AP_TREASURY = "TREASURY";
bytes32 constant AP_GEAR_TOKEN = "GEAR_TOKEN";
bytes32 constant AP_WETH_TOKEN = "WETH_TOKEN";
bytes32 constant AP_ROUTER = "ROUTER";
bytes32 constant AP_BOT_LIST = "BOT_LIST";
bytes32 constant AP_GEAR_STAKING = "GEAR_STAKING";
bytes32 constant AP_ZAPPER_REGISTER = "ZAPPER_REGISTER";

bytes32 constant AP_INFLATION_ATTACK_BLOCKER = "INFLATION_ATTACK_BLOCKER";
bytes32 constant AP_DEGEN_DISTRIBUTOR = "DEGEN_DISTRIBUTOR";
bytes32 constant AP_MULTI_PAUSE = "MULTI_PAUSE";

bytes32 constant AP_BYTECODE_REPOSITORY = "BYTECODE_REPOSITORY";
bytes32 constant AP_PRICE_FEED_STORE = "PRICE_FEED_STORE";

bytes32 constant AP_DEGEN_NFT = "DEGEN_NFT";
bytes32 constant AP_MARKET_CONFIGURATOR = "MARKET_CONFIGURATOR";
bytes32 constant AP_MARKET_CONFIGURATOR_LEGACY = "MARKET_CONFIGURATOR::LEGACY";

bytes32 constant AP_POOL_FACTORY = "POOL_FACTORY";
bytes32 constant AP_CREDIT_FACTORY = "CREDIT_FACTORY";
bytes32 constant AP_INTEREST_RATE_MODEL_FACTORY = "INTEREST_RATE_MODEL_FACTORY";
bytes32 constant AP_PRICE_ORACLE_FACTORY = "PRICE_ORACLE_FACTORY";
bytes32 constant AP_RATE_KEEPER_FACTORY = "RATE_KEEPER_FACTORY";
bytes32 constant AP_LOSS_POLICY_FACTORY = "LOSS_POLICY_FACTORY";
bytes32 constant AP_MARKET_CONFIGURATOR_FACTORY = "MARKET_CONFIGURATOR_FACTORY";

bytes32 constant DOMAIN_ACCOUNT_FACTORY = "ACCOUNT_FACTORY";
bytes32 constant DOMAIN_BOT = "BOT";
bytes32 constant DOMAIN_POOL = "POOL";
bytes32 constant DOMAIN_CREDIT_MANAGER = "CREDIT_MANAGER";
bytes32 constant DOMAIN_ADAPTER = "ADAPTER";
bytes32 constant DOMAIN_DEGEN_NFT = "DEGEN_NFT";
bytes32 constant DOMAIN_LOSS_POLICY = "LOSS_POLICY";
bytes32 constant DOMAIN_RATE_KEEPER = "RATE_KEEPER";
bytes32 constant DOMAIN_PRICE_FEED = "PRICE_FEED";
bytes32 constant DOMAIN_IRM = "IRM";
bytes32 constant DOMAIN_ZAPPER = "ZAPPER";

// ----- //
// ROLES //
// ----- //

bytes32 constant ROLE_EMERGENCY_LIQUIDATOR = "EMERGENCY_LIQUIDATOR";
bytes32 constant ROLE_PAUSABLE_ADMIN = "PAUSABLE_ADMIN";
bytes32 constant ROLE_UNPAUSABLE_ADMIN = "UNPAUSABLE_ADMIN";
