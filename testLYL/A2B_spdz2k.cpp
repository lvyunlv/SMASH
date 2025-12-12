#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "emp-aby/spdz2k.hpp"
#include "A2B_spdz2k.hpp"
#include <iostream>
#include <vector>
#include <thread>
#include <cassert>
#include <mcl/vint.hpp>
#include <random>
using namespace emp;
using namespace std;
int party, port;
const static int threads = 32;
int num_party;
const int l = 32;
const uint64_t FIELD_SIZE = 1ULL << 63;
int op = 1; 
int num = 1;
int main(int argc, char** argv) {
    BLS12381Element::init();
    if(argc < 5){
        cout << "Usage: <party> <port> <num_party> <nwc> [ip_file]" << endl;
        return 0;
    }
    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);
    string nwc = argv[4];
    vector<pair<string,unsigned short>> net_config;
    if(argc >= 6){
        FILE* f = fopen(argv[5], "r");
        if(f){
            for(int i=0;i<num_party;i++){
                char ip[128];
                unsigned int p;
                if(fscanf(f,"%127s %u", ip, &p)!=2){
                    cerr<<"Error reading IP config file"<<endl;
                    exit(1);
                }
                net_config.emplace_back(ip,(unsigned short)p);
            }
            fclose(f);
        }
    }
    if((int)net_config.size() != num_party){
        net_config.clear();
        for(int i=0;i<num_party;i++){
            net_config.emplace_back("127.0.0.1", port+i);
        }
    }
    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party, num_party, net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);
    Fr alpha_fr = alpha_init(num);
    string tablefile = "2";
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, tablefile, alpha_fr, num, op);
    lvt->DistKeyGen(1);
    for (int i = 0; i < l; ++i) lvt->generate_shares_(lvt->lut_share, lvt->rotation, lvt->table);
    TinyMAC<MultiIOBase> tiny(elgl);
    SPDZ2k<MultiIOBase> spdz2k(elgl);
    uint64_t x_spdz2k = spdz2k.rng() % FIELD_SIZE;
    SPDZ2k<MultiIOBase>::LabeledShare x_arith = spdz2k.distributed_share(x_spdz2k);
    nt(nwc); double total_time = 0, total_comm = 0, online_time = 0, online_comm = 0;
    int times = 1;
    for(int i=0;i<times;i++){
        auto x_bool = A2B_spdz2k::A2B(elgl, lvt, tiny, spdz2k, party, num_party, nwc, io, &pool, FIELD_SIZE, l, x_arith, online_time, online_comm);
        total_time += online_time;
        total_comm += online_comm;
    }
    // cout << "Average time: " << (total_time/times) << "ms && Average communication: " << (total_comm/times) << "KB" << endl;
    delete elgl; delete io; delete lvt;
    return 0;
}
