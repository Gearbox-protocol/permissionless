// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2025.
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

import {CreditFacadeV3} from "@gearbox-protocol/core-v3/contracts/credit/CreditFacadeV3.sol";

import {IBytecodeRepository} from "../../interfaces/IBytecodeRepository.sol";
import {Bytecode} from "../../interfaces/Types.sol";
import {AP_CREDIT_FACADE} from "../../libraries/ContractLiterals.sol";

import {InstanceManagerHelper} from "../helpers/InstanceManagerHelper.sol";
import {TestKeys} from "../helpers/TestKeys.sol";

import {VmSafe} from "forge-std/Vm.sol";

/// @dev Foundry's Gas struct gained `gasStateUsed` for EIP-8037; forge-std in this repo is still on the old layout.
struct GasAmsterdam {
    uint64 gasLimit;
    uint64 gasTotalUsed;
    uint64 gasMemoryUsed;
    int64 gasRefunded;
    uint64 gasRemaining;
    uint64 gasStateUsed;
}

interface VmAmsterdamGas {
    function lastCallGas() external view returns (GasAmsterdam memory gas);
}

/// @notice Measures BCR `uploadBytecode` gas for a ~24KB initcode (CreditFacadeV3) under Amsterdam rules.
///
/// Run (set `GLAMSTERDAM_FORK_RPC` to a Glamsterdam Sepolia RPC, e.g. in `.env`):
///   forge test --match-path contracts/test/suite/GlamsterdamBcrUploadGas.t.sol \
///     --evm-version amsterdam --hardfork amsterdam -vvv --isolate
contract GlamsterdamBcrUploadGasTest is Test, InstanceManagerHelper {
    VmAmsterdamGas internal constant vmA = VmAmsterdamGas(address(uint160(uint256(keccak256("hevm cheat code")))));

    VmSafe.Wallet internal bytecodeAuthor;
    uint256 internal blockGasLimit;

    function setUp() public {
        vm.createSelectFork(vm.envString("GLAMSTERDAM_FORK_RPC"));
        blockGasLimit = block.gaslimit;

        // CCG / BCR EIP-712 domains are hardcoded to chainId 1; upload on mainnet requires author == msg.sender.
        vm.chainId(1);

        TestKeys testKeys = new TestKeys();
        bytecodeAuthor = testKeys.bytecodeAuthor();

        _deployInstanceManager(testKeys.initialSigners(), testKeys.threshold(), testKeys.dao().addr);
    }

    function _isTestMode() internal pure override returns (bool) {
        return true;
    }

    function test_Glamsterdam_uploadCreditFacadeBytecode_fitsBlockGasLimit() public {
        console.log("fork block.gaslimit", blockGasLimit);
        assertGe(blockGasLimit, 190_000_000, "expected Glamsterdam Sepolia ~200M block gas limit");

        bytes memory initCode = type(CreditFacadeV3).creationCode;
        console.log("CreditFacadeV3 initcode bytes", initCode.length);
        assertGe(initCode.length, 20_000, "expected ~24KB CreditFacade initcode");
        assertLe(initCode.length, 24_576, "initcode exceeds legacy 24KB deployed-size era");

        Bytecode memory bytecode = Bytecode({
            contractType: AP_CREDIT_FACADE,
            version: 3_10,
            initCode: initCode,
            author: bytecodeAuthor.addr,
            source: "github.com/gearbox-protocol/core-v3",
            authorSignature: ""
        });

        bytes32 BYTECODE_TYPEHASH = IBytecodeRepository(bytecodeRepository).BYTECODE_TYPEHASH();
        bytes32 bytecodeHash = keccak256(
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
            _sign(bytecodeAuthor, keccak256(abi.encodePacked("\x19\x01", _bytecodeDomainSeparator(), bytecodeHash)));

        vm.prank(bytecodeAuthor.addr);
        IBytecodeRepository(bytecodeRepository).uploadBytecode(bytecode);

        GasAmsterdam memory g = vmA.lastCallGas();
        uint256 execGas = uint256(g.gasTotalUsed);
        uint256 stateGas = uint256(g.gasStateUsed);
        uint256 billable = execGas > stateGas ? execGas : stateGas;

        console.log("uploadBytecode CreditFacadeV3");
        console.log("  execution gas", execGas);
        console.log("  state gas    ", stateGas);
        console.log("  billable max ", billable);
        console.log("  block headroom", blockGasLimit > billable ? blockGasLimit - billable : 0);

        assertTrue(IBytecodeRepository(bytecodeRepository).isBytecodeUploaded(bytecodeHash), "bytecode not uploaded");
        assertTrue(execGas <= blockGasLimit, "uploadBytecode execution gas exceeds block");
        assertTrue(stateGas <= blockGasLimit, "uploadBytecode state gas exceeds block");
        assertTrue(billable <= blockGasLimit, "uploadBytecode exceeds block gas limit");
    }
}
