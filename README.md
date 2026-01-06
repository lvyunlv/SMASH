# SMASH: Scalable Maliciously Secure Hybrid Multi-party Computation Framework for Privacy-Preserving Large Language Model
    This repository is built on ScalableMixedModeMPC (https://github.com/radhika1601/ScalableMixedModeMPC)

# Installation

### Build this project

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

```console
mkdir build && cd build && cmake .. && make -j8
```

# Running tests
```console
cd bin
./test_gen_File 
```

All tests are run in SMASH/build/bin. 

```console
bash ../../Test_scripts/bert_nonlinear_malicious.sh
bash ../../Test_scripts/bert_nonlinear_semi.sh
```
```console
bash ../../Test_scripts/online_10k_1server.sh
bash ../../Test_scripts/online_10k_2server.sh
```
```console
bash ../../Test_scripts/qwen_nonlinear_malicious.sh
bash ../../Test_scripts/qwen_nonlinear_semi.sh
```
```console
bash ../../Test_scripts/semi_online_10k_1server.sh
bash ../../Test_scripts/semi_online_10k_2server.sh
```
```console
bash ../../Test_scripts/share_conversion.sh
```
```console
bash ../../Test_scripts/total_1server.sh
bash ../../Test_scripts/total_2server.sh
```
All results are saved in SMASH/Results.
