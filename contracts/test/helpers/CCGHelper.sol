// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {SignatureHelper} from "./SignatureHelper.sol";
import {CrossChainMultisig} from "../../../contracts/global/CrossChainMultisig.sol";
import {CrossChainCall, SignedProposal} from "../../../contracts/interfaces/ICrossChainMultisig.sol";

contract CCGHelper is SignatureHelper {
    // Core contracts
    CrossChainMultisig internal multisig;

    uint256 internal signer1Key;
    uint256 internal signer2Key;

    address internal signer1;
    address internal signer2;

    address internal dao;

    bytes32 prevProposalHash;

    function _setUpCCG() internal {
        signer1Key = _generatePrivateKey("SIGNER_1");
        signer2Key = _generatePrivateKey("SIGNER_2");
        signer1 = vm.addr(signer1Key);
        signer2 = vm.addr(signer2Key);

        dao = vm.addr(_generatePrivateKey("DAO"));

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

        prevProposalHash = 0;
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
}
