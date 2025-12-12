#include "emp-aby/BSGS.hpp"
#include "elgl/BLS12381Element.h"
#include <iostream>
#include <random>

const int thread_num = 4;
using namespace emp;
using namespace std;

int main() {
    BLS12381Element::init();
    BLS12381Element g = BLS12381Element::generator(); 

    cout << "g " << g.getPoint().b_.getUint64() << endl; 
    ThreadPool pool(thread_num);

    uint64_t N = 1ULL << 32; 
    BSGSPrecomputation bsgs;
     {
        auto start_time = chrono::high_resolution_clock::now();
        bsgs.precompute(g, N);
        auto end_time = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
        bsgs.serialize("bsgs_table.bin");
    }
    return 0;
}
