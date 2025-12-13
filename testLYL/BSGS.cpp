#include "emp-aby/BSGS.hpp"
#include "elgl/BLS12381Element.h"
#include <iostream>
#include <random>

const int thread_num = 32;
using namespace emp;
using namespace std;

int main() {
    BLS12381Element::init();
    BLS12381Element g = BLS12381Element::generator(); 

    // cout << "g " << g.getPoint().b_.getUint64() << endl; 
    ThreadPool pool(thread_num);

    uint64_t N = 1ULL << 40; 
    BSGSPrecomputation bsgs;
     {
        auto start_time = chrono::high_resolution_clock::now();
        bsgs.precompute(g, N);
        auto end_time = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
        bsgs.serialize("bsgs_table.bin");
    }
    uint64_t inpu = 1ULL << 32; 

    vector<BLS12381Element> y(100);
    for (int i=0 ;i < 100;i++)   y[i]  = g * Fr(inpu); 
    cout << inpu << endl;

    {
        auto start_time = chrono::high_resolution_clock::now();
        vector<int64_t> result = bsgs.solve_parallel_with_pool_vector(y, &pool, thread_num);
        auto end_time = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
        cout << "Discrete log result: " << result[7] << endl;
        cout << "Time taken: " << duration.count() << " milliseconds" << endl;
    }
    return 0;
}
