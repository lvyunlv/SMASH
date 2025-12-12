#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/spdz2k.hpp"
#include "A2L_spdz2k.hpp"
#include <iostream>
#include <vector>
#include <thread>
#include <cassert>

using namespace emp;
using namespace std;

int party, port;
const static int threads = 32;
int num_party;
const uint64_t FIELD_SIZE = 1ULL << 63;
const int num = 16;
int op = 32;

int main(int argc, char** argv){
    BLS12381Element::init();
    if(argc<5){ cout<<"Usage: <party> <port> <num_party> <nwc> [ip_config_file]"<<endl; return 0; }

    parse_party_and_port(argv,&party,&port);
    num_party = std::stoi(argv[3]);
    string nwc = argv[4];
    vector<pair<string,unsigned short>> net_config;
    if(argc>=6){
        FILE* f = fopen(argv[5],"r");
        if(f){for(int i=0;i<num_party;i++){char ip[128]; unsigned int p; if(fscanf(f,"%127s %u",ip,&p)!=2){cerr<<"Error reading IP file"<<endl; exit(1);} net_config.emplace_back(ip,(unsigned short)p);} fclose(f);}
    }
    if((int)net_config.size()!=num_party){net_config.clear(); for(int i=1;i<=num_party;i++) net_config.emplace_back("127.0.0.1", port+i-1);}
    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party,num_party,net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);
    Plaintext alpha;
    const mcl::Vint p("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    const mcl::Vint g("5");
    mcl::Vint n = mcl::Vint(1)<<num, alpha_vint;
    mcl::gmp::powMod(alpha_vint,g,(p-1)/n,p);
    alpha.assign(alpha_vint.getStr());
    Fr alpha_fr = alpha.get_message();
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl,"init",alpha_fr,num,op);
    lvt->DistKeyGen(1);
    SPDZ2k<MultiIOBase> spdz2k(elgl);
    if(party==1) for(int i=2;i<=num_party;i++) elgl->wait_for(i); else elgl->send_done(1);
    uint64_t x_spdz2k = spdz2k.rng()%FIELD_SIZE;
    SPDZ2k<MultiIOBase>::LabeledShare shared_x;
    shared_x.value = x_spdz2k; shared_x.mac = mulmod(x_spdz2k, spdz2k.mac_key, spdz2k_field_size); shared_x.owner = party; shared_x.field_size_ptr = &spdz2k_field_size;
    nt(nwc);
    double total_time=0, total_comm=0, online_time=0, online_comm=0;
    int times=1;
    for(int i=0;i<times;i++){
        auto [x, vec_cx] = A2L_spdz2k::A2L(elgl,lvt,spdz2k,party,num_party,io,&pool,shared_x,FIELD_SIZE,online_time,online_comm);
        total_time += online_time; total_comm += online_comm;
    }
    // cout << "Average time: " << (total_time/times) << "ms && Average communication: " << (total_comm/times) << "KB" << endl;
    delete elgl; delete io; delete lvt;
    return 0;
}
