#include "emp-aby/P2M.hpp"
#include "emp-aby/io/multi-io.hpp"
#include <iostream>
#include <random>

const int thread_num = 4;
using namespace emp;
using namespace std;

std::map<std::string, Fr> test_P_to_m(size_t max_exponent) {
    std::map<std::string, Fr> P_to_m;
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i <= max_exponent; ++i) {
        BLS12381Element g_i(i);
        P_to_m[g_i.getPoint().getStr()] = Fr(i);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    
    return P_to_m;
}

int main() {
    BLS12381Element::init();
    int num_party = 2;  
    int table_size = 17;  
    size_t max_exponent = (1ULL << table_size);  
    std::map<std::string, Fr> P_to_m;
    if (file_exists("P_to_m_table.bin")) {
        deserialize_P_to_m(P_to_m, "P_to_m_table.bin");
    } else {
        auto P_to_m = test_P_to_m(max_exponent);
        
        serialize_P_to_m(P_to_m, "P_to_m_table.bin");
    }
    
    auto start_time = chrono::high_resolution_clock::now();

    std::map<std::string, Fr> loaded_P_to_m;
    deserialize_P_to_m(loaded_P_to_m, "P_to_m_table.bin");
    
    BLS12381Element g(100000);
    auto it = loaded_P_to_m.find(g.getPoint().getStr());
    if (it == loaded_P_to_m.end()) {
        std::cerr << "[Error] pi_ask not found in P_to_m! pi_ask = " << g.getPoint().getStr() << std::endl;
        exit(1);
    }
    auto end_time = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);

    return 0;
}