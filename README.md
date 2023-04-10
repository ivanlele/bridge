# bridge_core_icp

Welcome to your new bridge_core_icp project and to the internet computer development community. By default, creating a new project adds this README and some template files to your project directory. You can edit these template files to customize your project and to include your own code to speed up the development cycle.

To get started, you might want to explore the project directory structure and the default configuration file. Working with this project in your development environment will not affect any production deployment or identity tokens.

To learn more before you start working with bridge_core_icp, see the following documentation available online:

- [Quick Start](https://internetcomputer.org/docs/quickstart/quickstart-intro)
- [SDK Developer Tools](https://internetcomputer.org/docs/developers-guide/sdk-guide)
- [Rust Canister Devlopment Guide](https://internetcomputer.org/docs/rust-guide/rust-intro)
- [ic-cdk](https://docs.rs/ic-cdk)
- [ic-cdk-macros](https://docs.rs/ic-cdk-macros)
- [Candid Introduction](https://internetcomputer.org/docs/candid-guide/candid-intro)
- [JavaScript API Reference](https://erxue-5aaaa-aaaab-qaagq-cai.raw.ic0.app)

If you want to start working on your project right away, you might want to try the following commands:

```bash
cd bridge_core_icp/
dfx help
dfx canister --help
```

## Running the project locally

```bash
# set up 
sh -ci "$(curl -fsSL https://internetcomputer.org/install.sh)"
# you MUST set some password
dfx identity new dfx_test_key
rustup target add wasm32-unknown-unknown


# deploy
dfx stop
dfx start --clean --background
dfx deploy
```

# Test data for the func
ac74c64A7cFdBb33c33D2827569FE6EaF9a677dB
100000
E86C4A45C1Da21f8838a1ea26Fc852BD66489ce9
5edcd76efb884194fc1f7d348ffc4ef93c611e3ffa89aca3a2dcf0131e2844df
0
11155111
true
goerli
