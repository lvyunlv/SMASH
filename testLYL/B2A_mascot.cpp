#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "emp-aby/mascot.hpp"
#include "B2A_mascot.hpp"
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
const mcl::Vint FIELD_SIZE("52435875175126190479447740508185965837690552500527637822603658699938581184512");
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
    MASCOT<MultiIOBase> mascot(elgl);
    vector<TinyMAC<MultiIOBase>::LabeledShare> x_bits(l);
    for(int i=0;i<l;i++){x_bits[i]=tiny.distributed_share(tiny.rng()%2);} nt(nwc);
    auto shared_x = B2A_mascot::B2A(elgl,lvt,tiny,mascot,party,num_party,nwc,io,&pool,FIELD_SIZE,x_bits);
    delete elgl; delete io; delete lvt;
    return 0;
}
