#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "emp-aby/mascot.hpp"
#include "A2B_mascot.hpp"
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
const int su = 32;
const mcl::Vint FIELD_SIZE("52435875175126190479447740508185965837690552500527637822603658699938581184512");
int kl = 1; 
int op = 1;

int main(int argc, char** argv) {
    BLS12381Element::init();
    if (argc < 5) {
        std::cout << "Usage: <PartyID> <port> <num_parties> <nwc> [ip_config_file]" << std::endl;
        return 0;
    }
    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);
    std::string nwc = argv[4];
    std::vector<std::pair<std::string, unsigned short>> net_config;
    if (argc >= 6) {
        const char* file = argv[5];
        FILE* f = fopen(file, "r");
        if (f != nullptr) {
            for (int i = 0; i < num_party; ++i) {
                char ip[128];
                unsigned int p;
                if (fscanf(f, "%127s %u", ip, &p) != 2) {
                    std::cerr << "[ERROR] Failed to read IP config at line " << i << std::endl;
                    fclose(f);
                    exit(1);
                }
                net_config.emplace_back(std::string(ip), (unsigned short)p);
            }
            fclose(f);
        } else {
            std::cerr << "[WARN] Cannot open IP config file " << file << ", fallback to localhost." << std::endl;
        }
    }

    if ((int)net_config.size() != num_party) {
        net_config.clear();
        for (int i = 0; i < num_party; ++i) {
            net_config.push_back({"127.0.0.1", static_cast<unsigned short>(port + 4*num_party*i)});
        }
    }
    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party, num_party, net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);
    Fr alpha_fr = alpha_init(op);
    std::string tablefile = "2";
    emp::LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, tablefile, alpha_fr, op, kl);
    lvt->DistKeyGen(1);
    for (int i = 0; i < su; ++i) lvt->generate_shares_(lvt->lut_share, lvt->rotation, lvt->table);
    TinyMAC<MultiIOBase> tiny(elgl);
    MASCOT<MultiIOBase> mascot(elgl);
    mcl::Vint x_mascot;
    x_mascot.setRand(FIELD_SIZE); 
    MASCOT<MultiIOBase>::LabeledShare x_arith = mascot.distributed_share(x_mascot);
    nt(nwc); double total_time = 0, total_comm = 0, online_time = 0, online_comm = 0;
    int times = 1;
    for (int i = 0; i < times; ++i) {
        auto x_bool = A2B_mascot::A2B(elgl, lvt, tiny, mascot, party, num_party, nwc, io, &pool, FIELD_SIZE, su, x_arith, online_time, online_comm);
        total_time += online_time;
        total_comm += online_comm;
    }
    // std::cout << "Average time: " << (total_time/times) << "ms && Average communication: " << (total_comm/times) << "KB" << std::endl;
    delete lvt;
    delete elgl;
    delete io;
    return 0;
}
