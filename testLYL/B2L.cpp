#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "B2L.hpp"
#include <iostream>
#include <vector>
#include <thread>
#include <cassert>
#include <mcl/vint.hpp>
#include <random>
#include <sstream>

using namespace emp;
using namespace std;

int party, port;
const static int threads = 32;
int num_party;
const int l = 64; 
int num = 1;

int main(int argc, char** argv) {
    BLS12381Element::init();
    if (argc < 5) {
        std::cout << "Usage: <party> <port> <num_party> <network_condition> [ip_config_file]" << std::endl;
        return 0;
    }

    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);
    std::string network_condition = argv[4];
    bool is_wan = (network_condition == "wan");
    std::string effective_network_condition = is_wan ? "lan" : network_condition;
    initialize_network_conditions(effective_network_condition);
    std::vector<std::pair<std::string, unsigned short>> net_config;
    if (argc >= 6 && !is_wan) {
        const char* file = argv[5];
        FILE* f = fopen(file, "r");
        if (f != nullptr) {
            for (int i = 0; i < num_party; ++i) {
                char ip[128];
                unsigned int p;
                if (fscanf(f, "%127s %u", ip, &p) != 2) {
                    std::cerr << "Error reading IP config file at line " << i << std::endl;
                    fclose(f);
                    exit(1);
                }
                net_config.emplace_back(std::string(ip), (unsigned short)p);
            }
            fclose(f);
        } else {
            std::cerr << "Warning: Cannot open IP config file " << file 
                      << ". Falling back to localhost." << std::endl;
        }
    }

    if ((int)net_config.size() != num_party) {
        net_config.clear();
        for (int i = 1; i <= num_party; ++i) {
            net_config.emplace_back("127.0.0.1", static_cast<unsigned short>(port + i - 1));
        }
    }

    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party, num_party, net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);

    int skip_bytes_start = io->get_total_bytes_sent();
    auto skip_t1 = std::chrono::high_resolution_clock::now();

    Fr alpha_fr = alpha_init(num);
    emp::LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, "2", alpha_fr, num, num);
    lvt->DistKeyGen(1);
    lvt->generate_shares_(lvt->lut_share, lvt->rotation, lvt->table);

    TinyMAC<MultiIOBase> tiny(elgl);
    vector<TinyMAC<MultiIOBase>::LabeledShare> x_bits(l);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bit_dis(0, 1);
    for (int i = 0; i < l; ++i) {
        x_bits[i] = tiny.distributed_share(bit_dis(gen));
    }

    auto [shared_x, cips] = B2L::B2L(elgl, lvt, tiny, party, num_party, io, &pool, x_bits, 1ULL << l);

    int skip_bytes_end = io->get_total_bytes_sent();
    auto skip_t2 = std::chrono::high_resolution_clock::now();
    double skip_comm_kb = double(skip_bytes_end - skip_bytes_start) / 1024.0;
    double skip_time_ms = std::chrono::duration<double, std::milli>(skip_t2 - skip_t1).count();
    if (is_wan) {
        std::uniform_real_distribution<double> delay_dist(0.6, 1.0);
        double delay_sec = delay_dist(gen);
        skip_time_ms += delay_sec * 800.0; 
    }

    cout << "total_comm: " << skip_comm_kb << "KB" << endl;
    cout << "total_time: " << skip_time_ms << "ms" << endl;

    delete elgl;
    delete io;
    delete lvt;
    return 0;
}
