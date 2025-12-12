#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/mascot.hpp"
#include "L2A_mascot.hpp"
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
const mcl::Vint FIELD_SIZE("52435875175126190479447740508185965837690552500527637822603658699938581184512");
const int num = 16; 
int op = 32; 

int main(int argc, char** argv) {
    BLS12381Element::init();
    if(argc<5){ cout<<"Usage: <party> <port> <num_party> <network_condition> [ip_file]"<<endl; return 0; }

    parse_party_and_port(argv,&party,&port);
    num_party = std::stoi(argv[3]);
    string network_condition = argv[4];
    bool is_wan = (network_condition=="wan");
    string effective_network_condition = is_wan ? "lan" : network_condition;
    initialize_network_conditions(effective_network_condition);

    vector<pair<string,unsigned short>> net_config;
    if(argc>=6 && !is_wan){
        FILE* f = fopen(argv[5],"r");
        if(f){for(int i=0;i<num_party;i++){char ip[128]; unsigned int p; if(fscanf(f,"%127s %u",ip,&p)!=2){cerr<<"IP file error"<<endl; exit(1);} net_config.emplace_back(ip,(unsigned short)p);} fclose(f);}
    }
    if((int)net_config.size()!=num_party){net_config.clear(); for(int i=1;i<=num_party;i++) net_config.emplace_back("127.0.0.1", port+i-1);}

    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party,num_party,net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party,io,&pool,party);

    Plaintext alpha;
    const mcl::Vint p("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    const mcl::Vint g("5"); 
    mcl::Vint n = mcl::Vint(1)<<num, alpha_vint;
    mcl::gmp::powMod(alpha_vint,g,(p-1)/n,p);
    alpha.assign(alpha_vint.getStr());
    Fr alpha_fr = alpha.get_message();

    LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party,party,io,&pool,elgl,"init",alpha_fr,num,op);
    lvt->DistKeyGen(1);

    MASCOT<MultiIOBase> mascot(elgl);
    if(party==1) for(int i=2;i<=num_party;i++) elgl->wait_for(i); else elgl->send_done(1);

    mcl::Vint x_mascot; x_mascot.setRand(FIELD_SIZE);
    Plaintext x; x.assign(x_mascot.getStr());
    Ciphertext cx = lvt->global_pk.encrypt(x);

    vector<Ciphertext> vec_cx(num_party);
    vec_cx[party-1] = cx;
    elgl->serialize_sendall(cx);
    for(int i=1;i<=num_party;i++) if(i!=party){Ciphertext cx_i; elgl->deserialize_recv(cx_i,i); vec_cx[i-1]=cx_i;}

    MASCOT<MultiIOBase>::LabeledShare shared_x;
    double total_time=0,total_comm=0,online_time=0,online_comm=0;
    int times=1;
    for(int i=0;i<times;i++){
        shared_x = L2A_mascot::L2A(elgl,lvt,mascot,party,num_party,io,&pool,x,vec_cx,FIELD_SIZE,online_time,online_comm,is_wan);
        total_time+=online_time; total_comm+=online_comm;
    }
    cout << "Average time: " << (total_time/times) << "ms && Average communication: " << (total_comm/times) << "KB" << endl;

    delete elgl; delete io; delete lvt;
    return 0;
}
