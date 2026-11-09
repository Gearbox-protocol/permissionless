# Glamsterdam (EIP-8037 / EIP-8038) Gas Impact Report

**Scope:** `permissionless`, `core-v3`, `integrations-v3` (with notes on adjacent `bots-v3`)  
**Focus:** BCR / factory market deployment, bytecode upload, hard-coded gas stipends, and Glamsterdam gas-invariant triage (INV-1 … INV-8)  
**Date:** 2026-11-09  
**Method:** Static review + CREATE/code-deposit floors + Glamsterdam Sepolia fork measurements via Foundry (`--evm-version amsterdam --hardfork amsterdam`, `lastCallGas().gasStateUsed`)

---

## Executive summary

Permissionless market deployment is **viable on Glamsterdam Sepolia (~200M block gas limit) only as separate transactions**. Each of `createMarketConfigurator`, `createMarket`, and `createCreditSuite` fits alone; their combined state-gas bill is ~**221M** and exceeds one block.

There is **no production `gasleft()` billing**, no production ETH `transfer`/`send` stipends, and no EIP-7702 setup in these repos. On-chain correctness risks from the Glamsterdam invariant set are limited:

| Topic | Verdict |
|---|---|
| Market / credit suite deploy vs ~200M block | **OK as 3 txs**; sum does not fit one block |
| BCR `uploadBytecode` (CreditFacade ~24KB) | **OK** (~38.7M billable) |
| `OptionalCall` fixed caps (10k / 30k) | **Operational INV-4** — raise/measure if getters get expensive; users cannot force stipend grief if probes stay cheap |
| Liquidator unlock `0 ↔ account` (INV-2) | **Pattern only** — no classic failure-write bug |
| Runtime opens / liquidations / adapters | **Cost / liveness** — re-estimate gas; not silent logic bugs |

---

## Glamsterdam gas model (relevant bits)

EIP-8037 introduces a separate **state-gas** dimension for new state (accounts, code, fresh slots). EIP-8038 raises related access costs. Practical prices used in this analysis:

| Operation | Pre-Amsterdam (approx.) | Amsterdam |
|---|---|---|
| Code deposit | 200 / byte | **1,530 / byte** (state gas) |
| CREATE2 to empty address (excl. init + deposit) | 32,000 | 12,000 + **183,600** state ≈ **195,600** |
| New account (value transfer / create) | 25,000 | **183,600** state |
| Cold SSTORE zero → nonzero | 22,100 | ≈ **110,020** (incl. **97,920** state) |
| State-gas reservoir | — | Only when `tx.gas > 2^24` (16,777,216); below that, state gas comes from `gasleft()` |

Transaction caps under EIP-8037:

- **Execution gas:** `TX_MAX_GAS_LIMIT` = `2^24` ≈ 16.7M  
- **Total `tx.gas`:** `TX_MAX_TOTAL_GAS_LIMIT` = `2^32 − 1` ≈ 4.3B (state gas can ride above the execution cap via the reservoir)

**Block gas (Glamsterdam Sepolia):** ~**200M** (EIP-1559 1/1024 voting; observed fork values ~199.6–200.0M). Execution and state gas each compete against that block budget.

**Floor formula** (create + deposit only, excludes init execution / ctor SSTOREs / BCR SSTORE2 reads):

```text
195,600 + 1,530 × deployed_bytes
```

Anything above ~10.8KB deployed code needs `tx.gas > 2^24` so state gas can use the reservoir — and the **block still charges the full Amsterdam cost**.

### Foundry metering caveat

`--evm-version amsterdam` alone is not enough for correct EIP-8037 accounting in Foundry. Use:

```bash
--evm-version amsterdam --hardfork amsterdam
```

and read **both** `gasTotalUsed` and `gasStateUsed` from `lastCallGas()` (forge-std’s `Gas` struct may lag; tests in this repo use a local `GasAmsterdam` overlay). Plain `gasleft()` / forge “gas:” labels under-count state-heavy CREATE paths.

---

## Permissionless deployment architecture

Bytecode Repository (BCR) flow (simplified):

1. Author `uploadBytecode` → SSTORE2.write chunks (~24.5KB CREATE data contracts)  
2. Auditors / governance allow the bytecode  
3. Factories `BytecodeRepository.deploy` → read initcode from SSTORE2 → `CREATE2` with salt  
4. MarketConfigurator orchestrates multi-CREATE2 market + credit suite construction  

Infra is **full CREATE2** (not EIP-1167 clones). Clones appear later for credit accounts / some redeemers, not for MC / pool / CM / facade.

| Path | Contracts created (typical) | Style |
|---|---|---|
| `createMarketConfigurator` (minimal) | MC, ACL, ContractsRegister | 3× CREATE2 |
| `createMarket` (Tumbler + Aliased loss) | Pool + IRM + rate keeper + loss policy (+ related) | multi CREATE2 |
| `createCreditSuite` | AccountFactory, CM, Configurator, **Facade**, CA master | 4× CREATE2 + 1× CREATE |
| `uploadBytecode` (large) | SSTORE2 data contract(s) | CREATE + deposit ≈ initcode size |

Arithmetic **floors** (create+deposit only) already showed every multi-deploy path over a historical ~36M L1 block and over the `2^24` reservoir threshold. Live fork numbers below supersede floors for the ~200M Sepolia target.

---

## Measured: standard market deploy (Sepolia fork)

**Test:** `contracts/test/suite/GlamsterdamMarketDeployGas.t.sol`  
**RPC:** `GLAMSTERDAM_FORK_RPC` (env)  
**Run:**

```bash
forge test --match-path contracts/test/suite/GlamsterdamMarketDeployGas.t.sol \
  --evm-version amsterdam --hardfork amsterdam -vvv --isolate
```

Observed (representative run, `block.gaslimit ≈ 199,998,855`):

| Step | Execution gas | State gas | Billable `max(exec,state)` | vs ~200M |
|---|---:|---:|---:|---|
| `createMarketConfigurator` | 559,499 | **42,319,800** | 42.3M | fits |
| `createMarket` | 1,626,425 | **77,004,900** | 77.0M | fits |
| `createCreditSuite` | 1,260,165 | **101,801,610** | 101.8M | fits (~half a block) |
| **Sum (3 separate txs)** | 3,446,089 | **221,126,310** | **221.1M** | **exceeds one block** |

**Conclusion:** Keep the three steps as separate transactions (current UX already does). Do not pack all three into one block/tx. `createCreditSuite` is the tightest single step (~102M state gas).

---

## Measured: BCR CreditFacade upload

**Test:** `contracts/test/suite/GlamsterdamBcrUploadGas.t.sol`

| Metric | Value |
|---|---|
| CreditFacadeV3 initcode | **24,383** bytes |
| Execution gas | 1,606,552 |
| State gas | **38,666,160** |
| Billable | **~38.7M** |
| Headroom vs ~200M | ~161M |

**Conclusion:** Large single-bytecode uploads fit comfortably in a Glamsterdam Sepolia block. Still require `tx.gas ≫ 2^24` for the reservoir. Do not batch many large uploads / system CREATE2s in one CCG `executeBatch`.

---

## Measured: CreditFacade runtime gas (Amsterdam metering)

Temporary copy of `core-v3` `CreditFacade.gas.t.sol` was run under Amsterdam with `lastCallGas` (exec + `gasStateUsed`), then removed. Representative totals:

| Flow | Exec | State | Total |
|---|---:|---:|---:|
| Open + collateral | 376k | 1.23M | **1.61M** |
| Open + 1 swap | 500k | 1.62M | **2.12M** |
| Open + 2 swaps | 524k | 1.62M | **2.15M** |
| Open + quoted collateral | 621k | 1.92M | **2.54M** |
| Multicall 1 swap | 243k | 392k | **634k** |
| Multicall 2 swaps | 267k | 392k | **659k** |
| Multicall swap + quotas | 374k | 588k | **961k** |
| increaseDebt | 242k | 0 | **242k** |
| decreaseDebt | 252k | 0 | **252k** |
| Close (no debt) | 172k | 0 | **172k** |
| Close + debt | 297k | 0 | **297k** |
| Close + 2 tokens | 351k | 98k | **449k** |
| Close + 1 swap | 418k | 392k | **809k** |
| Liquidate underlying | 298k | 98k | **396k** |
| Liquidate 1 collateral | 511k | 294k | **805k** |
| Liquidate 2 collateral | 627k | 392k | **1.02M** |

State gas dominates opens (new slots / account touches). Debt-only and some close paths with no new storage stay near pure execution. These are **cost** changes for wallets/bots, not block-limit blockers.

Note: forking Glamsterdam Sepolia for the full core-v3 gas suite is incompatible with `TokensTestSuite` (mainnet token addresses); local `--hardfork amsterdam` was used instead.

---

## Gas-invariant triage (INV-1 … INV-8)

Definitions: [ethereum/glamsterdam-gas-invariants](https://github.com/ethereum/glamsterdam-gas-invariants).

### Production surfaces found

**Hard-coded gas on external calls (`OptionalCall`):**

| Location | Cap | Probe |
|---|---:|---|
| `core-v3` `PriceFeedValidationTrait` | 10_000 | `skipPriceCheck()` |
| `core-v3` `CreditFacadeV3` | 30_000 | `getPhantomTokenInfo()` |
| `core-v3` `CreditConfiguratorV3` | 30_000 | `getPhantomTokenInfo()` |
| `integrations-v3` `MidasAliasedLossPolicyV3` | 30_000 | `contractType()` |
| `permissionless` `NestedPriceFeeds` | 10_000 | nested `priceFeed*` |
| Adjacent: `bots-v3` `PartialLiquidationBotV3` | **10_000** | same phantom probe (stricter than facade) |

**INV-2-style unlock flags:**

| Location | Pattern |
|---|---|
| `integrations-v3` `MidasLiquidator` | `transferableRedeemerOwner`: `0 → account → 0` around facade liquidate |
| `integrations-v3` `SecuritizeLiquidator` | same |
| `core-v3` `ReentrancyGuardTrait` | rests at **1** (already INV-2-safe) |

**Absent in production:** `gasleft()` billing, ETH `.transfer`/`.send`, EIP-7702 auth/setup, on-chain hard-coded gas around BCR deploy.

### Per-invariant verdict

| INV | Theme | Gearbox verdict |
|---|---|---|
| INV-1 | Failed call + later durable write under reservoir | **Unlikely** — no “mark done forever after starved call” next to OptionalCall / unlock |
| INV-2 | Instant refill when clearing new slot in same tx | **Pattern match only** on liquidator unlocks; **no bug** with current control flow |
| INV-3 | Refund on revert / unchecked CREATE | **Unlikely** — BCR CREATE2 checked; no OOG-from-empty-revert billing |
| INV-4 | Fixed gas no longer enough | **Main residual** — OptionalCall caps + CREATE2/clone cost inflation + off-chain gas limits |
| INV-5 | `gasleft()` delta billing | **Clear** — no prod metering |
| INV-6 | 1/64 leftover enough to finalize failure | Couples with INV-1; **not present** in current liquidator / probe patterns |
| INV-7 | Stipends / reserves too small | **Unlikely** in prod (no transfer/send); OptionalCall overlaps INV-4 |
| INV-8 | 7702 auth reuse after OOG | **Unlikely** — no prod 7702 setup |

---

## OptionalCall (INV-4) deep dive

`OptionalCall.staticCallOptionalSafe` forwards `staticcall{gas: gasAllowance}` and treats failure / empty returndata as **“selector absent”**, not “retry with more gas.”

**Failure modes if a legitimate getter OOGs under the stipend:**

- Facade may skip phantom withdraw path  
- Configurator / NestedPriceFeeds may mis-classify feeds  
- Midas loss policy may miss `contractType` → wrong loss-liq gate  
- bots-v3 phantom probe at 10k is stricter than facade’s 30k  

**User-forced stipend grief:** Not a concern **if probed getters stay cheap**. A user cannot inflate the gas of a fixed-selector `staticcall` on an already-deployed view function beyond what that code path costs. Risk is **repricing / colder access / heavier getters**, not adversarial calldata bloat into the probe.

**Actions:**

1. Measure cold Amsterdam cost of each probed selector on representative tokens/feeds.  
2. Set allowance ≥ measured + margin; align bots-v3 phantom cap with facade.  
3. Prefer positive interface detection that does not collapse OOG into “absent.”

---

## INV-2 liquidator unlock deep dive

Classic EF INV-2 bug:

```text
lock = 1;                    // pay ~97,920 state
target.call{gas: tiny}(...); // starved → fails
lock = 0;                    // instant refill
failed[id] = true;           // durable write funded by refill
```

Midas / Securitize liquidators set `transferableRedeemerOwner`, call facade liquidate, then clear to zero. They **do not** catch a failed/starved call and then write durable “done/failed” state. If `liquidateCreditAccount` reverts, the whole tx reverts and the unlock never sticks.

So INV-2 here is:

- Instant ~98k accounting weirdness after a **successful** liquidation when clearing the flag  
- **Not** a “starve call → permanently brick / book wrong state” bug  

Optional hardening (not required for correctness today): `transient` storage for the unlock, or a non-zero resting sentinel (`address(1)` idle).

---

## Other residual issues (ops / cost)

Nothing further in the OptionalCall / INV-2 correctness class. Remaining items are mostly **INV-4 cost / liveness**:

1. **Runtime CREATE** — `Clones.clone` on open account / redeemers still pays new-account state gas (~183k) + small deposit; `allowAdapter` / facade upgrades are full CREATE2 (tens of M state gas possible).  
2. **First-time storage** — first write of balance / quota / enabled-token slots ≈ 110k instead of ~22k.  
3. **Off-chain senders** — keepers, routers, Safe/presigned txs, bots with fixed gas limits.  
4. **CCG batch packing** — many large CREATE2s / uploads in one `executeBatch` can exceed a block even if each alone fits.  
5. **Receipt indexing** — only if custom tooling assumes old gasUsed semantics (not deeply reviewed).

---

## Recommendations

1. **Document / enforce** market bootstrap as **three txs** (MC → market → credit suite); never one atomic multi-step deploy on Glamsterdam.  
2. Require **`tx.gas ≫ 2^24`** for any large CREATE2 / BCR upload; educate wallets and scripts.  
3. Re-estimate bot / frontend gas for open, liquidate, adapter deploy under Amsterdam (`lastCallGas` + `gasStateUsed`).  
4. Revisit **OptionalCall** allowances after measuring cold probe costs; fix bots-v3 10k vs facade 30k inconsistency.  
5. Avoid packing multiple large BCR uploads or system deploys into one CCG batch / one block.  
6. Optionally harden liquidator unlocks with transient storage or non-zero sentinel (hygiene, not a known exploit).  
7. Keep fork tests under `contracts/test/suite/Glamsterdam*.t.sol` as regression checks against Sepolia’s ~200M target.

---

## Appendix: how to reproduce

```bash
# From permissionless/
export GLAMSTERDAM_FORK_RPC=<glamsterdam-sepolia-rpc>

forge test --match-path contracts/test/suite/GlamsterdamMarketDeployGas.t.sol \
  --evm-version amsterdam --hardfork amsterdam -vvv --isolate

forge test --match-path contracts/test/suite/GlamsterdamBcrUploadGas.t.sol \
  --evm-version amsterdam --hardfork amsterdam -vvv --isolate
```

Runtime CreditFacade numbers were taken from a temporary Amsterdam-instrumented copy of `core-v3/contracts/test/gas/credit/CreditFacade.gas.t.sol` (deleted after the run).
