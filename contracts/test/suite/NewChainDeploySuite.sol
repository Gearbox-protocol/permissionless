// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

import {CrossChainMultisig, CrossChainCall} from "../../global/CrossChainMultisig.sol";
import {InstanceManager} from "../../global/InstanceManager.sol";
import {PriceFeedStore} from "../../global/PriceFeedStore.sol";
import {IBytecodeRepository} from "../../interfaces/IBytecodeRepository.sol";
import {IAddressProvider} from "../../interfaces/IAddressProvider.sol";
import {IInstanceManager} from "../../interfaces/IInstanceManager.sol";

import {IWETH} from "@gearbox-protocol/core-v3/contracts/interfaces/external/IWETH.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {
    AP_PRICE_FEED_STORE,
    AP_INTEREST_RATE_MODEL_FACTORY,
    AP_CREDIT_FACTORY,
    AP_POOL_FACTORY,
    AP_PRICE_ORACLE_FACTORY,
    AP_RATE_KEEPER_FACTORY,
    AP_MARKET_CONFIGURATOR_FACTORY,
    AP_LOSS_POLICY_FACTORY,
    AP_GOVERNOR,
    AP_POOL,
    AP_POOL_QUOTA_KEEPER,
    AP_PRICE_ORACLE,
    AP_MARKET_CONFIGURATOR,
    AP_ACL,
    AP_CONTRACTS_REGISTER,
    AP_INTEREST_RATE_MODEL_LINEAR,
    AP_RATE_KEEPER_TUMBLER,
    AP_RATE_KEEPER_GAUGE,
    AP_LOSS_POLICY_DEFAULT
} from "../../libraries/ContractLiterals.sol";
import {SignedProposal, Bytecode} from "../../interfaces/Types.sol";

import {CreditFactory} from "../../factories/CreditFactory.sol";
import {InterestRateModelFactory} from "../../factories/InterestRateModelFactory.sol";
import {LossPolicyFactory} from "../../factories/LossPolicyFactory.sol";
import {PoolFactory} from "../../factories/PoolFactory.sol";
import {PriceOracleFactory} from "../../factories/PriceOracleFactory.sol";
import {RateKeeperFactory} from "../../factories/RateKeeperFactory.sol";

import {MarketConfigurator} from "../../market/MarketConfigurator.sol";
import {MarketConfiguratorFactory} from "../../market/MarketConfiguratorFactory.sol";
import {ACL} from "../../market/ACL.sol";
import {ContractsRegister} from "../../market/ContractsRegister.sol";
import {Governor} from "../../market/Governor.sol";

import {PoolV3} from "@gearbox-protocol/core-v3/contracts/pool/PoolV3.sol";
import {PoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/pool/PoolQuotaKeeperV3.sol";
import {PriceOracleV3} from "@gearbox-protocol/core-v3/contracts/core/PriceOracleV3.sol";
import {LinearInterestRateModelV3} from "@gearbox-protocol/core-v3/contracts/pool/LinearInterestRateModelV3.sol";
import {TumblerV3} from "@gearbox-protocol/core-v3/contracts/pool/TumblerV3.sol";
import {GaugeV3} from "@gearbox-protocol/core-v3/contracts/pool/GaugeV3.sol";
import {DefaultLossPolicy} from "../../helpers/DefaultLossPolicy.sol";

import {DeployParams} from "../../interfaces/Types.sol";

contract NewChainDeploySuite is Test {
    // Test accounts
    uint256 internal signer1Key;
    uint256 internal signer2Key;
    uint256 internal auditorKey;
    uint256 internal authorKey;
    address internal author;
    address internal signer1;
    address internal signer2;
    address internal auditor;
    address internal dao;

    address internal riskCurator;

    address internal instanceOwner;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant GEAR = 0xBa3335588D9403515223F109EdC4eB7269a9Ab5D;
    address constant CHAINLINK_ETH_USD = 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;

    // Core contracts
    CrossChainMultisig internal multisig;
    InstanceManager internal instanceManager;
    address internal bytecodeRepository;

    bytes32 prevProposalHash = 0;

    function setUp() public {
        // simulate chainId 1
        if (block.chainid != 1) {
            vm.chainId(1);
        }

        // Generate random private keys and derive addresses
        signer1Key = _generatePrivateKey("SIGNER_1");
        signer2Key = _generatePrivateKey("SIGNER_2");
        auditorKey = _generatePrivateKey("AUDITOR");
        authorKey = _generatePrivateKey("AUTHOR");
        signer1 = vm.addr(signer1Key);
        signer2 = vm.addr(signer2Key);
        auditor = vm.addr(auditorKey);
        author = vm.addr(authorKey);
        riskCurator = vm.addr(_generatePrivateKey("RISK_CURATOR"));

        instanceOwner = vm.addr(_generatePrivateKey("INSTANCE_OWNER"));

        // Deploy initial contracts
        address[] memory initialSigners = new address[](2);
        initialSigners[0] = signer1;
        initialSigners[1] = signer2;

        // EACH NETWORK SETUP

        // Deploy CrossChainMultisig with 2 signers and threshold of 2
        multisig = new CrossChainMultisig(
            initialSigners,
            2, // threshold
            dao
        );

        // Deploy InstanceManager owned by multisig
        instanceManager = new InstanceManager(address(multisig));
        bytecodeRepository = instanceManager.bytecodeRepository();

        // Add initial auditor\
    }

    function _submitProposal(CrossChainCall[] memory calls) internal {
        vm.startPrank(dao);
        multisig.submitProposal(calls, prevProposalHash);
        vm.stopPrank();
    }

    function _signCurrentProposal() internal {
        bytes32[] memory currentProposalHashes = multisig.getCurrentProposalHashes();

        SignedProposal memory currentProposal = multisig.signedProposals(currentProposalHashes[0]);

        bytes32 proposalHash = multisig.hashProposal(currentProposal.calls, currentProposal.prevHash);

        bytes memory signature1 =
            _sign(signer1Key, keccak256(abi.encodePacked("\x19\x01", _ccmDomainSeparator(), proposalHash)));

        multisig.signProposal(proposalHash, signature1);

        bytes memory signature2 =
            _sign(signer2Key, keccak256(abi.encodePacked("\x19\x01", _ccmDomainSeparator(), proposalHash)));
        multisig.signProposal(proposalHash, signature2);

        prevProposalHash = proposalHash;
    }

    function _submitProposalAndSign(CrossChainCall[] memory calls) internal {
        _submitProposal(calls);
        _signCurrentProposal();
    }

    function _generateAddAuditorCall(address _auditor, string memory _name) internal returns (CrossChainCall memory) {
        return _buildCrossChainCallDAO(
            bytecodeRepository, abi.encodeCall(IBytecodeRepository.addAuditor, (_auditor, _name))
        );
    }

    function _generateAllowSystemContractCall(bytes32 _bytecodeHash) internal returns (CrossChainCall memory) {
        return _buildCrossChainCallDAO(
            bytecodeRepository, abi.encodeCall(IBytecodeRepository.allowSystemContract, (_bytecodeHash))
        );
    }

    function _generateDeploySystemContractCall(bytes32 _contractName, uint256 _version)
        internal
        returns (CrossChainCall memory)
    {
        return CrossChainCall({
            chainId: 0,
            target: address(instanceManager),
            callData: abi.encodeCall(InstanceManager.deploySystemContract, (_contractName, _version))
        });
    }

    function _generateActivateCall(address _instanceOwner, address _treasury, address _weth, address _gear)
        internal
        returns (CrossChainCall memory)
    {
        return CrossChainCall({
            chainId: 1,
            target: address(instanceManager),
            callData: abi.encodeCall(InstanceManager.activate, (_instanceOwner, _treasury, _weth, _gear))
        });
    }

    function _uploadByteCode(bytes memory _initCode, bytes32 _contractName, uint256 _version)
        internal
        returns (bytes32 bytecodeHash)
    {
        Bytecode memory bytecode = Bytecode({
            contractType: _contractName,
            version: _version,
            initCode: _initCode,
            author: author,
            source: "github.com/gearbox-protocol/core-v3",
            authorSignature: ""
        });

        // Generate EIP-712 signature for bytecode
        bytes32 BYTECODE_TYPEHASH = IBytecodeRepository(bytecodeRepository).BYTECODE_TYPEHASH();

        bytecodeHash = keccak256(
            abi.encode(
                BYTECODE_TYPEHASH,
                bytecode.contractType,
                bytecode.version,
                keccak256(bytecode.initCode),
                bytecode.author,
                keccak256(bytes(bytecode.source))
            )
        );

        bytecode.authorSignature =
            _sign(authorKey, keccak256(abi.encodePacked("\x19\x01", _bytecodeDomainSeparator(), bytecodeHash)));

        vm.prank(author);
        IBytecodeRepository(bytecodeRepository).uploadBytecode(bytecode);
    }

    function _uploadByteCodeAndSign(bytes memory _initCode, bytes32 _contractName, uint256 _version)
        internal
        returns (bytes32 bytecodeHash)
    {
        bytecodeHash = _uploadByteCode(_initCode, _contractName, _version);
        string memory reportUrl = "https://github.com/gearbox-protocol/security-review";

        // Build auditor signature
        bytes32 signatureHash = keccak256(
            abi.encode(
                keccak256("SignBytecodeHash(bytes32 bytecodeHash,string reportUrl)"),
                bytecodeHash,
                keccak256(bytes(reportUrl))
            )
        );

        // Sign the hash with auditor key
        bytes memory signature =
            _sign(auditorKey, keccak256(abi.encodePacked("\x19\x01", _bytecodeDomainSeparator(), signatureHash)));

        // Call signBytecodeHash with signature
        IBytecodeRepository(bytecodeRepository).signBytecodeHash(bytecodeHash, reportUrl, signature);
    }

    function _bytecodeDomainSeparator() internal view returns (bytes32) {
        // Get domain separator from BytecodeRepository contract
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("BYTECODE_REPOSITORY")),
                keccak256(bytes("310")),
                1,
                bytecodeRepository
            )
        );
    }

    function _ccmDomainSeparator() internal view returns (bytes32) {
        // Get domain separator from BytecodeRepository contract
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("CROSS_CHAIN_MULTISIG")),
                keccak256(bytes("310")),
                1,
                address(multisig)
            )
        );
    }

    function _buildCrossChainCallDAO(address _target, bytes memory _callData)
        internal
        view
        returns (CrossChainCall memory)
    {
        return CrossChainCall({
            chainId: 0,
            target: address(instanceManager),
            callData: abi.encodeCall(InstanceManager.configureGlobal, (_target, _callData))
        });
    }

    function _generatePrivateKey(string memory salt) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(salt)));
    }

    function _sign(uint256 privateKey, bytes32 bytecodeHash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, bytecodeHash);
        return abi.encodePacked(r, s, v);
    }

    struct SystemContract {
        bytes initCode;
        bytes32 contractType;
        uint256 version;
    }

    struct DeploySystemContractCall {
        bytes32 contractType;
        uint256 version;
    }

    function test_NCD() public {
        CrossChainCall[] memory calls = new CrossChainCall[](1);
        calls[0] = _generateAddAuditorCall(auditor, "Initial Auditor");
        _submitProposalAndSign(calls);

        SystemContract[19] memory systemContracts = [
            SystemContract({initCode: type(PoolFactory).creationCode, contractType: AP_POOL_FACTORY, version: 3_10}),
            SystemContract({initCode: type(CreditFactory).creationCode, contractType: AP_CREDIT_FACTORY, version: 3_10}),
            SystemContract({
                initCode: type(InterestRateModelFactory).creationCode,
                contractType: AP_INTEREST_RATE_MODEL_FACTORY,
                version: 3_10
            }),
            SystemContract({initCode: type(PriceFeedStore).creationCode, contractType: AP_PRICE_FEED_STORE, version: 3_10}),
            SystemContract({
                initCode: type(PriceOracleFactory).creationCode,
                contractType: AP_PRICE_ORACLE_FACTORY,
                version: 3_10
            }),
            SystemContract({
                initCode: type(RateKeeperFactory).creationCode,
                contractType: AP_RATE_KEEPER_FACTORY,
                version: 3_10
            }),
            SystemContract({
                initCode: type(MarketConfiguratorFactory).creationCode,
                contractType: AP_MARKET_CONFIGURATOR_FACTORY,
                version: 3_10
            }),
            SystemContract({initCode: type(Governor).creationCode, contractType: AP_GOVERNOR, version: 3_10}),
            SystemContract({initCode: type(PoolV3).creationCode, contractType: AP_POOL, version: 3_10}),
            SystemContract({
                initCode: type(PoolQuotaKeeperV3).creationCode,
                contractType: AP_POOL_QUOTA_KEEPER,
                version: 3_10
            }),
            SystemContract({
                initCode: type(LinearInterestRateModelV3).creationCode,
                contractType: AP_INTEREST_RATE_MODEL_LINEAR,
                version: 3_10
            }),
            SystemContract({initCode: type(TumblerV3).creationCode, contractType: AP_RATE_KEEPER_TUMBLER, version: 3_10}),
            SystemContract({initCode: type(GaugeV3).creationCode, contractType: AP_RATE_KEEPER_GAUGE, version: 3_10}),
            SystemContract({initCode: type(PriceOracleV3).creationCode, contractType: AP_PRICE_ORACLE, version: 3_10}),
            SystemContract({
                initCode: type(DefaultLossPolicy).creationCode,
                contractType: AP_LOSS_POLICY_DEFAULT,
                version: 3_10
            }),
            SystemContract({
                initCode: type(MarketConfigurator).creationCode,
                contractType: AP_MARKET_CONFIGURATOR,
                version: 3_10
            }),
            SystemContract({initCode: type(ACL).creationCode, contractType: AP_ACL, version: 3_10}),
            SystemContract({
                initCode: type(ContractsRegister).creationCode,
                contractType: AP_CONTRACTS_REGISTER,
                version: 3_10
            }),
            SystemContract({
                initCode: type(LossPolicyFactory).creationCode,
                contractType: AP_LOSS_POLICY_FACTORY,
                version: 3_10
            })
        ];

        uint256 len = systemContracts.length;

        DeploySystemContractCall[7] memory deployCalls = [
            DeploySystemContractCall({contractType: AP_PRICE_FEED_STORE, version: 3_10}),
            DeploySystemContractCall({contractType: AP_POOL_FACTORY, version: 3_10}),
            DeploySystemContractCall({contractType: AP_PRICE_ORACLE_FACTORY, version: 3_10}),
            DeploySystemContractCall({contractType: AP_INTEREST_RATE_MODEL_FACTORY, version: 3_10}),
            DeploySystemContractCall({contractType: AP_RATE_KEEPER_FACTORY, version: 3_10}),
            DeploySystemContractCall({contractType: AP_LOSS_POLICY_FACTORY, version: 3_10}),
            DeploySystemContractCall({contractType: AP_MARKET_CONFIGURATOR_FACTORY, version: 3_10})
        ];

        uint256 deployCallsLen = deployCalls.length;

        calls = new CrossChainCall[](len + deployCallsLen + 1);
        for (uint256 i = 0; i < len; i++) {
            bytes32 bytecodeHash = _uploadByteCodeAndSign(
                systemContracts[i].initCode, systemContracts[i].contractType, systemContracts[i].version
            );
            calls[i] = _generateAllowSystemContractCall(bytecodeHash);
        }

        for (uint256 i = 0; i < deployCallsLen; i++) {
            calls[len + i] = _generateDeploySystemContractCall(deployCalls[i].contractType, deployCalls[i].version);
        }

        calls[len + deployCallsLen] = _generateActivateCall(instanceOwner, address(0), WETH, GEAR);

        _submitProposalAndSign(calls);
        address ap = instanceManager.addressProvider();

        address mcf = IAddressProvider(ap).getAddressOrRevert(AP_MARKET_CONFIGURATOR_FACTORY, 3_10);

        address poolFactory = IAddressProvider(ap).getAddressOrRevert(AP_POOL_FACTORY, 3_10);

        // PRICE_FEED_STORE
        _addPriceFeed(CHAINLINK_ETH_USD, 3600);
        _allowPriceFeed(WETH, CHAINLINK_ETH_USD);

        IWETH(WETH).deposit{value: 1e18}();
        IERC20(WETH).transfer(poolFactory, 1e18);

        vm.startPrank(riskCurator);
        address mc = MarketConfiguratorFactory(mcf).createMarketConfigurator(
            riskCurator, riskCurator, "Test Risk Curator", false
        );

        address pool = MarketConfigurator(mc).previewPoolAddress(3_10, WETH, "Test Market", "TM");

        MarketConfigurator(mc).createMarket({
            minorVersion: 3_10,
            underlying: WETH,
            name: "Test Market",
            symbol: "TM",
            interestRateModelParams: DeployParams(
                "LINEAR", abi.encode(uint16(100), uint16(200), uint16(100), uint16(100), uint16(200), uint16(300), false)
            ),
            rateKeeperParams: DeployParams("TUMBLER", abi.encode(pool, 7 days)),
            lossPolicyParams: DeployParams("DEFAULT", abi.encode(pool, ap)),
            underlyingPriceFeed: CHAINLINK_ETH_USD
        });
        vm.stopPrank();
    }

    function _allowPriceFeed(address token, address _priceFeed) internal {
        address ap = instanceManager.addressProvider();
        address priceFeedStore = IAddressProvider(ap).getAddressOrRevert(AP_PRICE_FEED_STORE, 3_10);
        vm.prank(instanceOwner);
        instanceManager.configureLocal(
            priceFeedStore, abi.encodeCall(PriceFeedStore.allowPriceFeed, (token, _priceFeed))
        );
    }

    function _addPriceFeed(address _priceFeed, uint32 _stalenessPeriod) internal {
        address ap = instanceManager.addressProvider();
        address priceFeedStore = IAddressProvider(ap).getAddressOrRevert(AP_PRICE_FEED_STORE, 3_10);
        vm.prank(instanceOwner);
        instanceManager.configureLocal(
            priceFeedStore, abi.encodeCall(PriceFeedStore.addPriceFeed, (_priceFeed, _stalenessPeriod))
        );
    }
}
