# Beldex Testnet Faucet

A testnet faucet backend and frontend for Beldex, built in C++ with Crow, CPR, SQLite, and other dependencies included as submodules.

## How to Clone the Repository

Clone the main repository and initialize submodules:

```bash
git clone --recurse-submodules https://github.com/MogamboPuri/beldex-testnet-faucet.git
cd beldex-testnet-faucet
```

If you already cloned without `--recurse-submodules`, run:

```bash
git submodule update --init --recursive
```

## Build Instructions

1. Create the build directory:

```bash
mkdir build
cd build
```

2. Run CMake and build:

```bash
cmake ..
make
```

## Run the Faucet

Once built, run the faucet binary:

```bash
./Beldex-faucet
```

The server will start (usually on http://localhost:5000 or your configured port).
