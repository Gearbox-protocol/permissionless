import { defineConfig } from "@wagmi/cli";
import { foundry } from "@wagmi/cli/plugins";

export default defineConfig({
  out: "./generated.ts",
  contracts: [],
  plugins: [
    foundry({
      include: [
        "AddressProvider.sol/AddressProvider.json",
        "IBytecodeRepository.sol/**.json",
        "ICrossChainMultisig.sol/**.json",
        "PriceFeedStore.sol/**.json",
        "IInstanceManager.sol/**.json",
        "IMarketConfiguratorFactory.sol/**.json",
        "IMarketConfigurator.sol/**.json",
        "IPoolConfigureActions.sol/**.json",
        "IPriceOracleConfigureActions.sol/**.json",
        "ICreditConfigureActions.sol/**.json",
      ],
    }),
  ],
});
