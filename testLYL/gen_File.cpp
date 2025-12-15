#include <iostream>
#include <vector>
#include <string>
#include "emp-aby/lvt.h"
#include "libelgl/elgl/Plaintext.h"
using namespace std;
std::mt19937_64 rng;
const static int threads = 32;
int main(int argc, char** argv) {
    // if (argc < 2) {
    //     std::cout << "please input a number" << std::endl;
    //     return 0;
    // }
    // int num = std::stoi(argv[1]);
    BLS12381Element::init();
    vector<int64_t> table;
    table.resize(1ULL<<28);
    Plaintext p;
    ThreadPool pool(threads);
    
    size_t n = table.size();
    size_t chunk = (n + threads - 1) / threads;

    for (int t = 0; t < threads; ++t) {
        size_t start = t * chunk;
        size_t end = std::min(start + chunk, n);
        pool.enqueue([&, start, end]() {
            for (size_t i = start; i < end; ++i) {
                table[i] = i;
            }
        });
    }
    serializeTable(table, "table_init.txt", table.size());

    table.resize(2);
    for (size_t i = 0; i < 2; i++){
        table[i] = i;
    }
    serializeTable(table, "table_2.txt", table.size());
    return 0;
}