// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

import {CrossChainMultisig, CrossChainCall} from "../../global/CrossChainMultisig.sol";
import {InstanceManager} from "../../global/InstanceManager.sol";
import {PriceFeedStore} from "../../global/PriceFeedStore.sol";
import {IBytecodeRepository} from "../../interfaces/IBytecodeRepository.sol";

import {AP_PRICE_FEED_STORE} from "../../libraries/ContractLiterals.sol";
import {SignedProposal, Bytecode} from "../../interfaces/Types.sol";

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

    // Core contracts
    CrossChainMultisig internal multisig;
    InstanceManager internal instanceManager;
    address internal bytecodeRepository;

    function setUp() public {
        // simulate chainId 1
        vm.chainId(1);

        // Generate random private keys and derive addresses
        signer1Key = _generatePrivateKey("SIGNER_1");
        signer2Key = _generatePrivateKey("SIGNER_2");
        auditorKey = _generatePrivateKey("AUDITOR");
        authorKey = _generatePrivateKey("AUTHOR");
        signer1 = vm.addr(signer1Key);
        signer2 = vm.addr(signer2Key);
        auditor = vm.addr(auditorKey);
        author = vm.addr(authorKey);
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

    function _submitProposal(CrossChainCall[] memory calls, bytes32 prevProposal) internal {
        vm.startPrank(dao);
        multisig.submitProposal(calls, prevProposal);
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
    }

    function _generateAddAuditorCall(address _auditor, string memory _name) internal returns (CrossChainCall memory) {
        return _buildCrossChainCallDAO(
            bytecodeRepository, abi.encodeCall(IBytecodeRepository.addAuditor, (_auditor, _name))
        );
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

    function test_NCD() public {
        CrossChainCall[] memory calls = new CrossChainCall[](1);
        calls[0] = _generateAddAuditorCall(auditor, "Initial Auditor");
        _submitProposal(calls, 0);
        _signCurrentProposal();

        _uploadByteCodeAndSign(type(PriceFeedStore).creationCode, AP_PRICE_FEED_STORE, 3_10);
    }
}
