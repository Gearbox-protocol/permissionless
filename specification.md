# Bytecode Repository Specification

## 1. Introduction

The Bytecode Repository is a secure, organized ledger for storing and sharing smart contract bytecode intended for cross-chain deployments. By offering a single point of reference, the repository ensures that the same contract version across different chains is indeed the identical, verified piece of code—reducing discrepancies and improving trust in multi-chain environments.

## 2. Purpose

Below is an updated Purpose section incorporating your newly provided points. We’ll keep the existing content but expand it to address permissionless deployment, verified code use for risk curators, and the modular architecture for developers.

You can integrate this into the broader spec once you’re satisfied. Let me know if you’d like any further modifications or if you’d like to add more details in other sections.

## 2. Purpose

This Bytecode Repository supports Gearbox  DAO in becoming a fully permissionless protocol and ecosystem for multi-chain and modular deployments. Its main objectives are:
- **Facilitating Permissionless Deployments**: By housing a verified catalog of smart contracts and their bytecode, the Repository ensures that anyone can deploy a Gearbox instance on any EVM-compatible environment (including roll-ups), without requiring special permission.
- **Safeguarding Against Malicious Code**: Risk curators, auditors, and developers can reliably use the Repository to verify that a contract’s bytecode is genuine and non-malicious. Since only validated and attested versions reside in the Repository, building on top of Gearbox becomes safer and more transparent.
- **Promoting a Modular, Plugin-Based Architecture**: Developers are encouraged to create new plugins and modules that extend Gearbox functionality—such as new interest rate models, rates keepers, etc. By submitting these modules’ bytecodes to the Repository, developers enable risk curators to easily browse, verify, and integrate new features, making the ecosystem more robust and innovative.

## 3. Definitions
-	**Contract Name**: A unique identifier stored as bytes32 that succinctly describes the contract’s functionality. Examples include "POOL", "CREDIT_MANAGER", or "IRM_DEFAULT".
-	**Domain**: A group of smart contracts that share the same purpose and interface but may have different implementations. Example: An IRM (Interest Rate Model) domain could include variations such as IRM_LINEAR, IRM_TWO_POINTS, or IRM_AUTO. Each uses a distinct algorithm to calculate interest rates but follows the same core interface.
-	**Postfix**: A suffix appended to the domain to indicate a specific implementation. Examples: In the IRM context, the postfixes "_LINEAR", "_TWO_POINTS", and "_AUTO" produce the full contract names IRM_LINEAR, IRM_TWO_POINTS, or IRM_AUTO.
-	**Version**: A numeric labeling scheme following major-minor-patch semantics:
    -	**Major increments**: (often multiplied by 100) denote significant, potentially breaking changes.
    -	**Minor increments**: represent feature additions, which may also be breaking changes depending on context.
    -	**Patch increments**: address small updates or bug fixes.
    For instance, 3_1_2 can be interpreted as:
    -	3: Major version (e.g., “Version 3” contracts)
    -	1: Minor version (an iteration or feature addition on Version 3)
    -	2: Patch version (small fixes within Version 3.1)
- **Token-Specific Postfixes**: A suffix appended to the domain to indicate a specialized or unique contract version that inherits from a base contract but differs when used with specific tokens.
Example: A “USDT pool” postfix might be required if the pool needs special fee computation to accommodate USDT’s behavior, ensuring compatibility without errors.
- **Auditors**: A specialized role that issues cryptographic proofs or attestations regarding a particular version of bytecode. The list of recognized auditors is maintained via DAO voting, allowing a Gearbox DAO to add or remove auditors from the official registry.

## 4. IVersion interface
Each contract must implement the following interface to facilitate self-identification of its version and type. Both parameters should be represented by constant values within the contract:

```solidity
interface IVersion {
    /// @notice Contract version
    function version() external view returns (uint256);

    /// @notice Contract type
    function contractType() external view returns (bytes32);
}
```

## 5. Public and system domains
Below is a proposed Chapter 5 on Public and System Domains, incorporating the details you provided. Feel free to adjust headings, formatting, or wording as needed.

## 5. Public and System Domains
In the Bytecode Repository, domains are grouped into two categories: **public** and **system**. This distinction ensures that developers can freely introduce new functionality while preserving the security and integrity of core Gearbox contracts.

#### 5.1 Public Domains
- **Open Submission**: Public domains allow any developer to submit their own contract implementations. For example, a developer may create a new interest rate model (IRM), combining the domain name IRM with a postfix like _CUSTOM_LINEAR to distinguish it from other implementations.
- **Ownership and Updates**: Once a developer submits a new contract name (e.g., IRM_CUSTOM_LINEAR) and an auditor provides a valid signature attesting to its bytecode, the name becomes owned by that developer. Only the owner can update or replace the bytecode under that exact name. This mechanism prevents mixing of different implementations under the same identifier.
- **Guard Against Cybersquatting**: Because an auditor’s signature is required for a name to be finalized, malicious parties cannot easily cybersquat popular or well-known contract names. Even if an auditor mistakenly (or maliciously) signs a submission for someone who is not the rightful owner:
	1.	A special DAO transaction can remove the offending auditor from the approved auditors list, as signing for the wrong party constitutes malicious behavior.
	2.	The DAO vote would also release that contract name, freeing it up for legitimate ownership and usage.

#### 5.2 System Domains
- **Core Gearbox Contracts**: System domains store the bytecode for essential Gearbox contracts, such as factories, market configurators, credit managers, and other infrastructural components critical to the protocol.
- **DAO-Governed Updates**: Any update to the bytecode under system domains requires an on-chain vote by the Gearbox DAO. This extra layer of governance ensures that core protocol components cannot be modified without community consensus.
Any update to the bytecode under system domains requires an on-chain vote by the Gearbox DAO. This extra layer of governance ensures that core protocol components cannot be modified without community consensus.
- **Security and Trust**: By segregating core contracts into system domains, the protocol maintains a clear boundary between foundational Gearbox functionality and the optional modules or plugins in public domains. DAO oversight further reduces the risk of malicious or accidental changes to mission-critical infrastructure.

Below is a concise Section 6 with the updated struct.

## 6. Uploading New Bytecodes

To add a new contract implementation, a developer must invoke uploadBytecode(...) on Ethereum Mainnet. This ensures a single, trusted source of truth. After upload, one or more approved auditors can sign the bytecode to confirm its authenticity.

#### 6.1 BytecodeMetaData Struct

```solidity
struct BytecodeMetaData {
    bytes32 contractType;
    bytes32 postfix;
    uint256 version;
    bytes bytecode;     // Also store its hash
    string source;      // Could be a link to source code
    address author;     // Automatically set to msg.sender
}
```

`bytecodeMetaHash` is computed as `keccak256(abi.encode(contractType, postfix, version, keccak256(bytecode)))`. This hash uniquely identifies the bytecode metadata and is used for auditor signatures and cross-chain verification.


#### 6.2 Workflow
1.	**Developer Upload**
•	Calls uploadBytecode(...) on Mainnet, providing contractType, postfix, version, bytecode, and source.
•	The contract sets author to msg.sender.
2.	**Auditor Signatures**
•	Approved auditors verify the uploaded bytecode. They can sign a EIP-712 signature and provide it in a method `signBytecodeMetaHash(...)` with following parameters: `bytecodeMetaHash`, `reportUrl`, `r`, `s`, `v`.

The signatures are stored in the `auditorSignatures` mapping. To support cross-chain deployment, the EIP-712 domain signature skips chainId, so if it's signed once, it's valid on any EVM-compatible chain.

Auditors signatures are stored in the `auditorSignatures` mapping with the following structure:

```solidity
struct AuditorSignature {
    string reportUrl;
    bytes32 r;
    bytes32 s;
    uint8 v;
}
```
•	If valid, they provide on-chain signatures.

3.	**Cross-Chain Deployment**
•	Once signed on Mainnet, the bytecode can be securely referenced and deployed on any EVM-compatible network. The mainnet contract can returned signed structure and in could be uploaded on any network. To sync the list of apporved auditors cross-chain instance managers is used.