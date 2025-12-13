#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "emp-aby/spdz2k.hpp"
#include "B2A_spdz2k.hpp"
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
const uint64_t FIELD_SIZE = (1ULL<<63);
int op = 1; 
int num = 1;
int main(int argc, char** argv){
    BLS12381Element::init();
    if(argc<5){cout<<"Format: <PartyID> <port> <num_parties> <nwc> [ip_file]"<<endl; return 0;}
    parse_party_and_port(argv,&party,&port);
    num_party = std::stoi(argv[3]);
    string nwc = argv[4];
    vector<pair<string,unsigned short>> net_config;
    if(argc>=6){
        FILE* f = fopen(argv[5],"r");
        if(f){for(int i=0;i<num_party;i++){char ip[128]; unsigned int p; if(fscanf(f,"%127s %u",ip,&p)!=2){cerr<<"IP file error"<<endl; exit(1);} net_config.emplace_back(ip,(unsigned short)p);} fclose(f);}
    }
    if((int)net_config.size()!=num_party){net_config.clear(); for(int i=0;i<num_party;i++) net_config.push_back({"127.0.0.1", port+4*num_party*i});}
    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party,num_party,net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party,io,&pool,party);
    Fr alpha_fr = alpha_init(num);
    string tablefile="2";
    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party,party,io,&pool,elgl,tablefile,alpha_fr,num,op);
    lvt->DistKeyGen(1);
    TinyMAC<MultiIOBase> tiny(elgl);
    SPDZ2k<MultiIOBase> spdz2k(elgl);
    vector<TinyMAC<MultiIOBase>::LabeledShare> x_bits(l);
    for(int i=0;i<l;i++){x_bits[i]=tiny.distributed_share(tiny.rng()%2);}nt(nwc);
    int comm = io->get_total_bytes_sent();
    auto time = std::chrono::high_resolution_clock::now();
    lvt->generate_shares(lvt->lut_share, lvt->rotation, lvt->table);nta();
    for (int i=1;i<l;++i) lvt->generate_shares(lvt->lut_share, lvt->rotation, lvt->table);
    auto shared_x = B2A_spdz2k::B2A(elgl,lvt,tiny,spdz2k,party,num_party,nwc,io,&pool,FIELD_SIZE,x_bits,time,comm);
    delete elgl; delete io; delete lvt;
    return 0;
}
