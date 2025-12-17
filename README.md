# SMASH: Scalable Maliciously Secure Hybrid Multi-party Computation Framework for Privacy-Preserving Large Language Model
    This repository is built on ScalableMixedModeMPC (https://github.com/radhika1601/ScalableMixedModeMPC)

# Installation

### Build this project

1. Clone the repository.

```console
git clone https://github.com/Rhyme595L/SMASH.git
cd SMASH
```

### Dependencies

1. `wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py`
2. `python install.py --install --tool --ot`
    1. By default it will build for Release. `-DCMAKE_BUILD_TYPE=[Release|Debug]` option is also available.
    2. No sudo? Change [`CMAKE_INSTALL_PREFIX`](https://cmake.org/cmake/help/v2.8.8/cmake.html#variable%3aCMAKE_INSTALL_PREFIX).
    3. On Mac [homebrew](https://brew.sh/) is needed for installation. 
3. Install openFHE
    ```console
    git clone https://github.com/openfheorg/openfhe-development.git --branch v1.0.4
    cd openfhe-development && mkdir build && cd build
    cmake .. && make -j8 && sudo make install
    ```
### Build this project

1. Build using cmake.

```console
cmake .
make
```

# Running tests
```
cd Test_scripts
```
```
bert_nonlinear_malicious.sh
bert_nonlinear_semi.sh
```
```
online_10k_1server.sh
online_10k_2server.sh
```
```
qwen_nonlinear_malicious.sh
qwen_nonlinear_semi.sh
```
```
semi_online_10k_1server.sh
semi_online_10k_2server.sh
```
```
share_conversion.sh
```
```
total_1server.sh
total_2server.sh
```
