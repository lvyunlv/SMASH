#pragma once
#include "libelgl/elgl/BLS12381Element.h"
#include "emp-aby/utils.h"
#include "emp-aby/elgl_interface.hpp"
// #include "libelgl/elgl/FFT.h"
#include "libelgl/elgl/Ciphertext.h"
#include "libelgl/elgloffline/RotationProof.h"
#include "libelgl/elgloffline/RotationProver.h"
#include "libelgl/elgloffline/RotationVerifier.h"
#include "libelgl/elgloffline/Exp_proof.h"
#include "libelgl/elgloffline/Exp_prover.h"
#include "libelgl/elgloffline/Exp_verifier.h"

#include "libelgl/elgloffline/Range_Proof.h"
#include "libelgl/elgloffline/Range_Prover.h"
#include "libelgl/elgloffline/Range_Verifier.h"
#include "libelgl/elgl/FFT_Para_Optimized.hpp"
#include "emp-aby/BSGS.hpp"
#include "emp-aby/P2M.hpp"
// #include "libelgl/elgl/FFT_Para_AccelerateCompatible.hpp"

#if defined(__APPLE__) || defined(__MACH__)
    #include <filesystem>
    namespace fs = std::filesystem;
#else
    #include <experimental/filesystem>
    namespace fs = std::experimental::filesystem;
#endif

const int thread_num = 32;
// #include "cmath"
// #include <poll.h>

namespace emp{

void nt(const std::string& condition);


void deserializeTable(vector<int64_t>& table, const char* filename, size_t table_size = 1<<16) {
    ifstream inFile(filename, ios::binary);
    if (!inFile) {
        cerr << "Error: Unable to open file for reading.\n Error in 'file: " << filename << "'.";
        exit(1);
    }

    table.resize(table_size);  // 预分配空间
    inFile.read(reinterpret_cast<char*>(table.data()), table_size * sizeof(int64_t));

    // 计算实际读取的元素个数
    size_t elementsRead = inFile.gcount() / sizeof(int64_t);
    table.resize(elementsRead);  // 调整大小以匹配实际读取的内容

    inFile.close();
}

template <typename IO>
class LVT{
    public:
    int num_used = 0;
    ThreadPool* pool;
    BLS12381Element G_tbs;

    ELGL<IO>* elgl;
    MPIOChannel<IO>* io;
    // std::vector<Ciphertext> cr_i;
    Fr alpha;
    size_t su;
    size_t ad;
    // void shuffle(Ciphertext& c, bool* rotation, size_t batch_size, size_t i);

    ELGL_PK global_pk;
    Plaintext rotation;
    std::vector<ELGL_PK> user_pk;
    vector<Plaintext> lut_share;
    vector<vector<BLS12381Element>> cip_lut;
    emp::BSGSPrecomputation bsgs;
    std::map<std::string, Fr> P_to_m;
    BLS12381Element g;
    
    int num_party;
    int party;
    vector<int64_t> table;
    LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha, int table_size, int m_bits);
    LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, std::string tableFile, Fr& alpha, int table_size, int m_bits);
    static void initialize(std::string name, LVT<IO>*& lvt_ptr_ref, int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha_fr, int table_size, int m_bits);
    static void initialize_batch(std::string name, LVT<IO>*& lvt_ptr_ref, int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha_fr, int table_size, int m_bits);
    ELGL_PK DistKeyGen(bool offline);
    ~LVT();
    void generate_shares(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table);
    void generate_shares_(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table);
    Plaintext lookup_online(Plaintext& x_share);
    vector<Plaintext> lookup_online_batch(vector<Plaintext>& x_share);
    void save_full_state(const std::string& filename);
    void load_full_state(const std::string& filename);
    Plaintext Reconstruct(Plaintext input, vector<Ciphertext> input_cips, ELGL<IO>* elgl, const ELGL_PK& global_pk, const std::vector<ELGL_PK>& user_pks, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, mcl::Vint modulo);
    Plaintext Reconstruct_interact(Plaintext input, Ciphertext input_cip, ELGL<IO>* elgl, const ELGL_PK& global_pk, const std::vector<ELGL_PK>& user_pks, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, mcl::Vint modulo);
    Plaintext Reconstruct_easy(Plaintext input, ELGL<IO>* elgl, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, mcl::Vint modulo);

    LVT(): num_party(0), party(0), io(nullptr), pool(nullptr), elgl(nullptr), alpha(Fr()), su(0), ad(0) {};
};

template <typename IO>
void LVT<IO>::save_full_state(const std::string& filename) {
    std::ofstream out(filename, std::ios::binary);
    if (!out) throw std::runtime_error("Failed to open file for writing");
    
    size_t total_size = sizeof(int) * 2 +  
                       sizeof(size_t) * 2 + 
                       sizeof(Fr) +         
                       su * sizeof(Fr) + 
                       sizeof(Fr) +        
                       sizeof(size_t) +   
                       table.size() * sizeof(int64_t) + 
                       num_party * su * sizeof(G1) + 
                       num_party * 2 * sizeof(G1) +  
                       sizeof(G1) +        
                       num_party * sizeof(G1) +
                       sizeof(Fr) +        
                       sizeof(G1) * 2;     

    std::vector<char> buffer(total_size);
    char* ptr = buffer.data();
    memcpy(ptr, &num_party, sizeof(int)); ptr += sizeof(int);
    memcpy(ptr, &party, sizeof(int)); ptr += sizeof(int);
    memcpy(ptr, &su, sizeof(size_t)); ptr += sizeof(size_t);
    memcpy(ptr, &ad, sizeof(size_t)); ptr += sizeof(size_t);

    const Fr& rot_fr = rotation.get_message();
    memcpy(ptr, &rot_fr, sizeof(Fr)); ptr += sizeof(Fr);
    
    for (size_t i = 0; i < su; i++) {
        const Fr& fr = lut_share[i].get_message();
        memcpy(ptr, &fr, sizeof(Fr)); ptr += sizeof(Fr);
    }
    
    const Fr& sk_fr = elgl->kp.get_sk().get_sk();
    memcpy(ptr, &sk_fr, sizeof(Fr)); ptr += sizeof(Fr);
    
    size_t table_size = table.size();
    memcpy(ptr, &table_size, sizeof(size_t)); ptr += sizeof(size_t);
    memcpy(ptr, table.data(), table_size * sizeof(int64_t)); ptr += table_size * sizeof(int64_t);
    
    for (int i = 0; i < num_party; ++i) {
        for (size_t j = 0; j < su; ++j) {
            const G1& point = cip_lut[i][j].getPoint();
            memcpy(ptr, &point, sizeof(G1)); ptr += sizeof(G1);
        }
    }
    const G1& global_point = global_pk.get_pk().getPoint();
    memcpy(ptr, &global_point, sizeof(G1)); ptr += sizeof(G1);
    
    for (int i = 0; i < num_party; ++i) {
        const G1& user_point = user_pk[i].get_pk().getPoint();
        memcpy(ptr, &user_point, sizeof(G1)); ptr += sizeof(G1);
    }

    memcpy(ptr, &alpha, sizeof(Fr)); ptr += sizeof(Fr);

    const G1& g_tbs_point = G_tbs.getPoint();
    memcpy(ptr, &g_tbs_point, sizeof(G1)); ptr += sizeof(G1);

    const G1& g_point = g.getPoint();
    memcpy(ptr, &g_point, sizeof(G1));
    
    out.write(buffer.data(), total_size);
    out.close();
}

template <typename IO>
void LVT<IO>::load_full_state(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    if (!in) throw std::runtime_error("Failed to open file for reading");
    
    in.seekg(0, std::ios::end);
    size_t file_size = in.tellg();
    in.seekg(0, std::ios::beg);
    
    std::vector<char> buffer(file_size);
    in.read(buffer.data(), file_size);
    const char* ptr = buffer.data();
    
    memcpy(&num_party, ptr, sizeof(int)); ptr += sizeof(int);
    memcpy(&party, ptr, sizeof(int)); ptr += sizeof(int);
    memcpy(&su, ptr, sizeof(size_t)); ptr += sizeof(size_t);
    memcpy(&ad, ptr, sizeof(size_t)); ptr += sizeof(size_t);
    
    Fr rot_fr;
    memcpy(&rot_fr, ptr, sizeof(Fr)); ptr += sizeof(Fr);
    rotation.set_message(rot_fr);
    
    lut_share.resize(su);
    for (size_t i = 0; i < su; i++) {
        Fr fr;
        memcpy(&fr, ptr, sizeof(Fr)); ptr += sizeof(Fr);
        lut_share[i].set_message(fr);
    }
    
    Fr sk_fr;
    memcpy(&sk_fr, ptr, sizeof(Fr)); ptr += sizeof(Fr);
    ELGL_SK key;
    key.sk = sk_fr;
    elgl->kp.sk = key;
    
    size_t table_size;
    memcpy(&table_size, ptr, sizeof(size_t)); ptr += sizeof(size_t);
    table.resize(table_size);
    memcpy(table.data(), ptr, table_size * sizeof(int64_t)); ptr += table_size * sizeof(int64_t);

    cip_lut.resize(num_party);
    for (int i = 0; i < num_party; ++i) {
        cip_lut[i].resize(su);
        for (size_t j = 0; j < su; ++j) {
            G1 point;
            memcpy(&point, ptr, sizeof(G1)); ptr += sizeof(G1);
            BLS12381Element elem;
            elem.point = point;
            cip_lut[i][j] = elem;
        }
    }
    
    // cr_i.resize(num_party);
    for (int i = 0; i < num_party; ++i) {
        G1 c0, c1;
        memcpy(&c0, ptr, sizeof(G1)); ptr += sizeof(G1);
        memcpy(&c1, ptr, sizeof(G1)); ptr += sizeof(G1);
        
        BLS12381Element e0, e1;
        e0.point = c0;
        e1.point = c1;
        // cr_i[i] = Ciphertext(e0, e1);
    }
    
    G1 global_point;
    memcpy(&global_point, ptr, sizeof(G1)); ptr += sizeof(G1);
    BLS12381Element global_elem;
    global_elem.point = global_point;
    global_pk.assign_pk(global_elem);
    
    user_pk.resize(num_party);
    for (int i = 0; i < num_party; ++i) {
        G1 user_point;
        memcpy(&user_point, ptr, sizeof(G1)); ptr += sizeof(G1);
        BLS12381Element user_elem;
        user_elem.point = user_point;
        user_pk[i].assign_pk(user_elem);
    }

    memcpy(&alpha, ptr, sizeof(Fr)); ptr += sizeof(Fr);

    G1 g_tbs_point;
    memcpy(&g_tbs_point, ptr, sizeof(G1)); ptr += sizeof(G1);
    G_tbs.point = g_tbs_point;
    G1 g_point;
    memcpy(&g_point, ptr, sizeof(G1));
    g.point = g_point;

    in.close();
}



template <typename IO>
LVT<IO>::LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha, int table_size, int m_bits){
    this->io = io;
    this->party = party;
    this->num_party = num_party;
    this->alpha = alpha;
    this->pool = pool;
    this->elgl = elgl;
    this->user_pk.resize(num_party);
    this->user_pk[party-1] = elgl->kp.get_pk();
    this->su = 1ULL << table_size;
    this->ad = 1ULL << m_bits;
    this->cip_lut.resize(num_party);
    // this->cr_i.resize(num_party);
    this->lut_share.resize(su);
    this->G_tbs = BLS12381Element(su);
    BLS12381Element::init();
    BLS12381Element g = BLS12381Element::generator();
    this->global_pk = DistKeyGen(1);
}

template <typename IO>
void LVT<IO>::initialize(std::string func_name, LVT<IO>*& lvt_ptr_ref, int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha_fr, int table_size, int m_bits) {
    std::string full_state_path = "../cache/lvt_" + func_name + "_size" + std::to_string(table_size) + "-P" + std::to_string(party) + ".bin";
    fs::create_directories("../cache");
    lvt_ptr_ref = new LVT<IO>(num_party, party, io, pool, elgl, func_name, alpha_fr, table_size, m_bits);
    if (fs::exists(full_state_path)) {
        auto start = clock_start();
        lvt_ptr_ref->load_full_state(full_state_path);
        std::cout << "Loading cached state time: " << std::fixed << std::setprecision(6) << time_from(start) / 1e6 << " seconds" << std::endl;
    } else {
        auto start = clock_start();
        cout << "Generating new state..." << endl;
        lvt_ptr_ref->generate_shares(lvt_ptr_ref->lut_share, lvt_ptr_ref->rotation, lvt_ptr_ref->table);
        cout << "Generate shares finished" << endl;
        lvt_ptr_ref->save_full_state(full_state_path);
        std::cout << "Generate and cache state time: " << std::fixed << std::setprecision(6) << time_from(start) / 1e6 << " seconds" << std::endl;
    }
}

template <typename IO>
LVT<IO>::LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, string func_name, Fr& alpha, int table_size, int m_bits)
    : LVT(num_party, party, io, pool, elgl, alpha, table_size, m_bits) {
    fs::create_directories("../cache");
    std::string tableFile = "../bin/table_" + func_name + ".txt";
    std::string table_cache = "../cache/table_" + func_name + "_" + std::to_string(table_size) + ".bin";
    std::string p_to_m_cache = "../cache/p_to_m_" + std::to_string(m_bits) + ".bin";
    std::string bsgs_cache = "../cache/bsgs_32.bin";
    if (fs::exists(table_cache)) {
        std::ifstream in(table_cache, std::ios::binary);
        if (!in) throw std::runtime_error("Failed to open table cache");
        
        size_t size;
        in.read(reinterpret_cast<char*>(&size), sizeof(size_t));
        table.resize(size);
        in.read(reinterpret_cast<char*>(table.data()), size * sizeof(int64_t));
        in.close();
    } else {
        deserializeTable(table, tableFile.c_str(), su);
        std::ofstream out(table_cache, std::ios::binary);
        if (!out) throw std::runtime_error("Failed to create table cache");
        
        size_t size = table.size();
        out.write(reinterpret_cast<const char*>(&size), sizeof(size_t));
        out.write(reinterpret_cast<const char*>(table.data()), size * sizeof(int64_t));
        out.close();
    }
    // if (m_bits <= 14) {
        if (fs::exists(p_to_m_cache)) {
            std::ifstream in(p_to_m_cache, std::ios::binary);
            if (!in) throw std::runtime_error("Failed to open P_to_m cache");
            
            size_t size;
            in.read(reinterpret_cast<char*>(&size), sizeof(size_t));
            P_to_m.clear();
            
            for (size_t i = 0; i < size; ++i) {
                size_t key_len;
                in.read(reinterpret_cast<char*>(&key_len), sizeof(size_t));
                std::string key(key_len, '\0');
                in.read(&key[0], key_len);
                
                Fr value;
                in.read(reinterpret_cast<char*>(&value), sizeof(Fr));
                P_to_m[key] = value;
            }
            in.close();
        } else {
            build_safe_P_to_m(P_to_m, 2 * su * num_party);
            std::ofstream out(p_to_m_cache, std::ios::binary);
            if (!out) throw std::runtime_error("Failed to create P_to_m cache");
            
            size_t size = P_to_m.size();
            out.write(reinterpret_cast<const char*>(&size), sizeof(size_t));
            
            for (const auto& pair : P_to_m) {
                size_t key_len = pair.first.length();
                out.write(reinterpret_cast<const char*>(&key_len), sizeof(size_t));
                out.write(pair.first.c_str(), key_len);
                out.write(reinterpret_cast<const char*>(&pair.second), sizeof(Fr));
            }
            out.close();
        }
    // }
    uint64_t N = 1ULL << 32;
    if (fs::exists(bsgs_cache)) {
        try {
            bsgs.deserialize(bsgs_cache.c_str());
        } catch (const std::exception& e) {
            bsgs.precompute(g, N);
            bsgs.serialize(bsgs_cache.c_str());
        }
    } else {
        bsgs.precompute(g, N);
        bsgs.serialize(bsgs_cache.c_str());
    }
}

template <typename IO>
void LVT<IO>::generate_shares(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table) {
    vector<std::future<void>> res;
    vector<BLS12381Element> c0;
    vector<BLS12381Element> c1;
    vector<BLS12381Element> c0_;
    vector<BLS12381Element> c1_;
    
    mcl::Vint bound;
    bound.setStr(to_string(su));

    c0.resize(su);
    c1.resize(su);
    c0_.resize(su);
    c1_.resize(su);
    ELGL_SK sbsk;
    ELGL_SK twosk;

    rotation.set_random(bound);
    vector<BLS12381Element> ak;
    vector<BLS12381Element> bk;
    vector<BLS12381Element> dk;
    vector<BLS12381Element> ek;
    ak.resize(su);
    bk.resize(su);
    dk.resize(su);
    ek.resize(su);
    mcl::Unit N(su);
    
    if(party == ALICE)
    {
        vector<Plaintext> x(su);
        for(size_t i = 0; i < su; i++){
            x[i] = Plaintext(Fr(this->table[i]));
        }
        vector<Plaintext> r1;
        r1.resize(su);
        for(size_t i = 0; i < su; i++){
            r1[i].set_random();
            c0[i] = BLS12381Element(r1[i].get_message());
            c1[i] =  global_pk.get_pk() * r1[i].get_message() + BLS12381Element(x[i].get_message());
        }
   
        // DFT
        res.push_back(pool->enqueue(
            [this, &c0, &ak, N]()
            {
                FFT_Para(c0, ak, this->alpha, N);     
            }
        ));
        res.push_back(pool->enqueue(
            [this, &c1, &bk, N]()
            {
                FFT_Para(c1, bk, this->alpha, N);
            }
        ));
        for (auto& f : res) {
            f.get();
        }
        res.clear();
    
        // 旋转
        Plaintext beta;
        vector<Plaintext> betak;
        betak.resize(su);

        Plaintext::pow(beta, alpha, rotation);
        vector<Plaintext> sk;
        sk.resize(su);
        for (size_t i = 0; i < su; i++){
            sk[i].set_random();
        }

        for (size_t i = 0; i < su; i++){
            res.push_back(pool->enqueue(
                [this, i, &dk, &ek, &sk, &ak, &bk, &beta]()
                {
                    Plaintext betak_;
                    Plaintext i_;
                    i_.assign(to_string(i));
                    Plaintext::pow(betak_, beta, i_);
                    dk[i] = BLS12381Element(1) * sk[i].get_message();
                    dk[i] += ak[i] * betak_.get_message();
                    // e_k = bk ^ betak * h^sk
                    ek[i] = global_pk.get_pk() * sk[i].get_message();
                    ek[i] += bk[i] * betak_.get_message();
                }
            ));
        }
        for (auto& f : res) {
            f.get();
        }
        res.clear();

        std::stringstream commit_ro, comm_ro_;
        for (size_t j = 0; j < su; j++)
        {
            dk[j].pack(commit_ro);
            ek[j].pack(commit_ro);
        }
        std::string comm_raw = commit_ro.str();
        comm_ro_ << base64_encode(comm_raw);
        // elgl->serialize_sendall_(comm_ro_);
        elgl->serialize_sendp2p(comm_ro_, party + 1);
    }

    // for (size_t i = 1; i <= num_party -1; i++){
    //     if (i == party) {
    //         continue;
    //     }else{
            // res.push_back(pool->enqueue([this, &dk, &ek, i, &rotation]() {
    else if (party > 1 && party < num_party){
        vector<BLS12381Element> dk_thread;
        vector<BLS12381Element> ek_thread;
        dk_thread.resize(su);
        ek_thread.resize(su);

        std::stringstream comm_ro;
        std::string comm_raw;
        std::stringstream comm_;
        elgl->deserialize_recv_(comm_ro, party - 1);
        comm_raw = comm_ro.str();
        comm_ << base64_decode(comm_raw);
        for (size_t j = 0; j < su; j++)
        {
            dk_thread[j].unpack(comm_);
            ek_thread[j].unpack(comm_);
        }

        // if (i == this->party)
        // {
            vector<BLS12381Element> dk_;
            vector<BLS12381Element> ek_;
            dk_.resize(su);
            ek_.resize(su);
            Plaintext beta;
            Plaintext::pow(beta, alpha, rotation);

            vector<Plaintext> sk;
            sk.resize(su);
            vector<std::future<void>> res_;
            for (size_t i = 0; i < su; i++){
                res_.push_back(pool->enqueue(
                    [this, i, &dk_, &ek_, &sk, &dk_thread, &ek_thread, &beta]()
                    {
                        Plaintext betak;
                        Plaintext i_;
                        i_.assign(to_string(i));
                        Plaintext::pow(betak, beta, i_);
                        dk_[i] = dk_thread[i] * betak.get_message();
                        ek_[i] = ek_thread[i] * betak.get_message();
                        sk[i].set_random();
                        dk_[i] += BLS12381Element(sk[i].get_message());
                        ek_[i] += global_pk.get_pk() * sk[i].get_message();
                    }
                ));
            }
            for (auto & f : res_) {
                f.get();
            }
            res_.clear();

            std::stringstream commit_ro;
            for (size_t j = 0; j < su; j++)
            {
                dk_[j].pack(commit_ro);
                ek_[j].pack(commit_ro);
            }
            std::stringstream comm_ro_final; 
            std::string comm_raw_final;
            comm_raw_final = commit_ro.str();
            comm_ro_final << base64_encode(comm_raw_final);         

            // elgl->serialize_sendall_(comm_ro_final);
            elgl->serialize_sendp2p(comm_ro_final, party + 1);

            // if (this->num_party == this->party){
            //         dk = dk_;
            //         ek = ek_;
            // }
    }
    //         }));
    //     }
    // }
    // for (auto& v : res)
    //     v.get();
    // res.clear();
    else{
        vector<BLS12381Element> dk_thread;
        vector<BLS12381Element> ek_thread;
        dk_thread.resize(su);
        ek_thread.resize(su);

        std::stringstream comm_ro;
        std::string comm_raw;
        std::stringstream comm_;
        elgl->deserialize_recv_(comm_ro, party - 1);
        comm_raw = comm_ro.str();
        comm_ << base64_decode(comm_raw);
        for (size_t j = 0; j < su; j++)
        {
            dk_thread[j].unpack(comm_);
            ek_thread[j].unpack(comm_);
        }

        // if (i == this->party)
        // {
            vector<BLS12381Element> dk_;
            vector<BLS12381Element> ek_;
            dk_.resize(su);
            ek_.resize(su);
            Plaintext beta;
            Plaintext::pow(beta, alpha, rotation);

            vector<Plaintext> sk;
            sk.resize(su);
            vector<std::future<void>> res_;
            for (size_t i = 0; i < su; i++){
                res_.push_back(pool->enqueue(
                    [this, i, &dk_, &ek_, &sk, &dk_thread, &ek_thread, &beta]()
                    {
                        Plaintext betak;
                        Plaintext i_;
                        i_.assign(to_string(i));
                        Plaintext::pow(betak, beta, i_);
                        dk_[i] = dk_thread[i] * betak.get_message();
                        ek_[i] = ek_thread[i] * betak.get_message();
                        sk[i].set_random();
                        dk_[i] += BLS12381Element(sk[i].get_message());
                        ek_[i] += global_pk.get_pk() * sk[i].get_message();
                    }
                ));
            }
            for (auto & f : res_) {
                f.get();
            }
            res_.clear();

            // IDFT
            Plaintext alpha_inv;
            Fr alpha_inv_;
            Fr::inv(alpha_inv_, alpha);
            alpha_inv.assign(alpha_inv_.getMpz());
            Fr N_inv;
            Fr::inv(N_inv, N);
            res.push_back(pool->enqueue(
                [this, &dk_, &c0_, &N, &alpha_inv]()
                {
                    FFT_Para(dk_, c0_, alpha_inv.get_message(), N);
                }
            ));
            res.push_back(pool->enqueue(
                [this, &ek_, &c1_, &N, &alpha_inv]()
                {
                    FFT_Para(ek_, c1_, alpha_inv.get_message(), N);
                }
            ));
            for (auto& f : res) {
                f.get();
            }
            res.clear();

            for (size_t i = 0; i < su; i++) {
                res.push_back(pool->enqueue([&c0_, &c1_, &N_inv, i]() {
                    c0_[i] *= N_inv;
                    c1_[i] *= N_inv;
                }));
            }
            for (auto& f : res) {
                f.get();
            }
            res.clear();


            std::stringstream commit_ro;
            for (size_t j = 0; j < su; j++)
            {
                c0_[j].pack(commit_ro);
                c1_[j].pack(commit_ro);
            }
            std::stringstream comm_ro_final; 
            std::string comm_raw_final;
            comm_raw_final = commit_ro.str();
            comm_ro_final << base64_encode(comm_raw_final);         

            elgl->serialize_sendall_(comm_ro_final);
    }

    if (party != num_party){
        std::stringstream comm_ro;
        std::string comm_raw;
        std::stringstream comm_;
        
        // elgl->deserialize_recv_(comm_ro, num_party);
        elgl->deserialize_recv_(comm_ro, num_party);
        comm_raw = comm_ro.str();
        comm_ << base64_decode(comm_raw);

        for (size_t j = 0; j < su; j++)
        {
            c0_[j].unpack(comm_);
            c1_[j].unpack(comm_);
        }
    }

    if (party == ALICE) {
        vector<Plaintext> y_alice;
        vector<BLS12381Element> L;
        L.resize(su);
        
        auto g = BLS12381Element::generator();
        Fr e = Fr(to_string((num_party - 1) * ad));
        BLS12381Element base = g * e; 
        vector<BLS12381Element> l_alice(su, base);
        
        vector<BLS12381Element> l_(num_party);
        for (size_t i = 2; i <= num_party; i++)
        {
            vector<BLS12381Element> y3;
            vector<BLS12381Element> y2;
            y2.resize(su);
            y3.resize(su);
            std::stringstream commit_ro;
            std::string comm_raw;
            std::stringstream comm_;
            // time 
            elgl->deserialize_recv_(commit_ro, i);
            comm_raw = commit_ro.str();
            comm_ << base64_decode(comm_raw);
            
            BLS12381Element pk__ = user_pk[i-1].get_pk();
            for (int j = 0; j < su; j++){
                y2[j].unpack(comm_);
                y3[j].unpack(comm_);
            }

            for (size_t j = 0; j < su; j++)
            {
                l_alice[j] -= y2[j];
            }
            cip_lut[i-1] = y3;
        }
        
        for (size_t i = 0; i < su; i++){
            res.push_back(pool->enqueue([&c1_, &l_alice, i]() {
                l_alice[i] += c1_[i];
            }));
        }
        for (auto& f : res) {
            f.get();
        }
        res.clear();

        cip_lut[0].resize(su);
        bool flag = 0; 
        if(ad <= 131072) flag = 1;
        for (size_t i = 0; i < su; i++){
                BLS12381Element Y = l_alice[i] - c0_[i] * elgl->kp.get_sk().get_sk(); 
                Y.getPoint().normalize();
                Fr y; 
                if(flag) {
                    auto it = this->P_to_m.find(Y.getPoint().getStr());
                    if (it == this->P_to_m.end()) {
                        std::cerr << "[Error] y not found in P_to_m! y = " << Y.getPoint().getStr() << std::endl;
                        exit(1);
                    } else {
                        y = it->second;
                    }
                } else 
                {   
                    cout << "solve_parallel_with_pool: " << i << endl;
                    y = this->bsgs.solve_parallel_with_pool(Y, pool, thread_num);
                }
                mcl::Vint r_;
                mcl::Vint y_;
                y_ = y.getMpz();
                mcl::Vint ms;  
                ms.setStr(to_string(this->ad));
                mcl::gmp::mod(r_, y_, ms);
                Fr r;
                r.setMpz(r_);
                lut_share[i].set_message(r);
                BLS12381Element l(r);
                l += c0_[i] * this->elgl->kp.get_sk().get_sk();
                L[i] = BLS12381Element(l);
                BLS12381Element pk_tmp = this->global_pk.get_pk();
                this->cip_lut[0][i] = BLS12381Element(r) + pk_tmp * this->elgl->kp.get_sk().get_sk();
        }
        // time

        std::stringstream commit_ss;
        std::string commit_raw;
        std::stringstream commit_b64_;
        
        // time prove
        for (unsigned int j = 0; j < su; ++j) {
            L[j].pack(commit_ss);
            cip_lut[0][j].pack(commit_ss);
        }   

        commit_raw = commit_ss.str();
        commit_b64_ << base64_encode(commit_raw);
        elgl->serialize_sendall_(commit_b64_);

        for (size_t i = 2; i <= num_party; i++)
         {
             res.push_back(pool->enqueue([this, i](){
                 this->elgl->wait_for(i);
             }));
         }
         for (auto& v : res)
             v.get();
         res.clear();

    }else{
        mcl::Vint bound(to_string(ad));
        std::stringstream commit_ss;
        vector<BLS12381Element> l_1_v;
        vector<BLS12381Element> cip_v;
        // time
        l_1_v.resize(su);
        cip_v.resize(su);

        for (size_t i = 0; i < su; i++) {
            lut_share[i].set_random(bound);
            BLS12381Element l_1, cip_;
            l_1 = BLS12381Element(lut_share[i].get_message());
            l_1 += c0_[i] * this->elgl->kp.get_sk().get_sk();
            l_1_v[i] = l_1;  

            cip_ = BLS12381Element(lut_share[i].get_message());
            cip_ += this->global_pk.get_pk() * this->elgl->kp.get_sk().get_sk();
            cip_v[i] = cip_;  
        }
        cip_lut[party-1] = cip_v;

        for (unsigned int j = 0; j < su; ++j) {
            l_1_v[j].pack(commit_ss);
            cip_v[j].pack(commit_ss);
        }

        std::stringstream commit_ra_;
        std::string commit_raw = commit_ss.str();
        commit_ra_ << base64_encode(commit_raw);
        // sendall
        elgl->serialize_sendall_(commit_ra_);
        // elgl->serialize_sendp2p(commit_ra_, ALICE);

        // receive all others commit and response
        for (size_t i = 2; i <= num_party; i++){
            if (i != party)
            {
                vector<BLS12381Element> y3;
                vector<BLS12381Element> y2;
                y3.resize(su);
                y2.resize(su);
                std::stringstream commit_ro;
                std::string comm_raw;
                std::stringstream comm_;
                elgl->deserialize_recv_(commit_ro, i);
                comm_raw = commit_ro.str();
                comm_ << base64_decode(comm_raw);
                BLS12381Element pk__ = user_pk[i-1].get_pk();
                for (int j = 0; j < su; j++){
                    y2[j].unpack(comm_);
                    y3[j].unpack(comm_);
                }
                cip_lut[i-1] = y3;
            }
        }

        std::stringstream commit_ro;
        std::string comm_raw_;
        std::stringstream comm_;
        elgl->deserialize_recv_(commit_ro, ALICE);
        comm_raw_ = commit_ro.str();
        comm_ << base64_decode(comm_raw_);
        vector<BLS12381Element> y2;
        vector<BLS12381Element> y3;
        y2.resize(su);
        y3.resize(su);
        BLS12381Element pk__ = user_pk[0].get_pk();
        for (int j = 0; j < su; j++){
            y2[j].unpack(comm_);
            y3[j].unpack(comm_);
        }
        cip_lut[0] = y3;
        elgl->send_done(ALICE);
    }

}


template <typename IO>
void LVT<IO>::generate_shares_(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table) {
    size_t n = table.size();
    lut_share.resize(su);
    cip_lut.assign(num_party, vector<BLS12381Element>());
    for (int p = 0; p < num_party; ++p) cip_lut[p].resize(su);
    rotation.set_message(0); Fr k=0;
    elgl->kp.sk.assign_sk(k);
    elgl->kp.pk = ELGL_PK(elgl->kp.sk);
    BLS12381Element tmp = BLS12381Element(0);
    this->global_pk.assign_pk(tmp);
    for (int p = 0; p < num_party; ++p) user_pk[p].assign_pk(tmp);
    BLS12381Element pk = this->global_pk.get_pk(); 
    BLS12381Element G = tmp;
    size_t tnum = std::max<size_t>(1, thread_num);
    size_t chosen_block_size = (n + tnum - 1) / tnum;
    if (chosen_block_size == 0) chosen_block_size = 1;
    bool is_consecutive = true;
    if (n > 0) {
        int64_t start = table[0];
        for (size_t i = 0; i < n; ++i) {
            if (table[i] != start + static_cast<int64_t>(i)) { is_consecutive = false; break; }
        }
    }
    for (int p = 1; p < num_party; ++p) {
        std::fill(cip_lut[p].begin(), cip_lut[p].begin() + n, pk);
    }
    vector<future<void>> tasks;
    tasks.reserve(tnum + 4);
    if (is_consecutive) {
        size_t idx = 0;
        while (idx < n) {
            size_t bstart = idx;
            size_t bend = std::min(n, bstart + chosen_block_size);
            tasks.push_back(pool->enqueue([this, bstart, bend, G, pk, &table]() {
                BLS12381Element start_point = BLS12381Element(static_cast<int64_t>(bstart + table[0]));
                BLS12381Element cur = start_point;
                for (size_t j = bstart; j < bend; ++j) {
                    cip_lut[0][j] = cur + pk; 
                    cur += G;
                }
            }));
            idx = bend;
        }
    } else {
        size_t idx = 0;
        while (idx < n) {
            size_t bstart = idx;
            size_t bend = std::min(n, bstart + chosen_block_size);
            tasks.push_back(pool->enqueue([this, bstart, bend, &table, pk]() {
                for (size_t j = bstart; j < bend; ++j) {
                    cip_lut[0][j] = BLS12381Element(table[j]) + pk;
                }
            }));
            idx = bend;
        }
    }
    for (auto &f : tasks) f.get();
    tasks.clear();
    if (party == 1) {
        size_t idx = 0;
        while (idx < n) {
            size_t bstart = idx;
            size_t bend = std::min(n, bstart + chosen_block_size);
            tasks.push_back(pool->enqueue([bstart, bend, &lut_share, &table]() {
                for (size_t j = bstart; j < bend; ++j) lut_share[j].set_message(table[j]);
            }));
            idx = bend;
        }
    } else {
        size_t idx = 0;
        while (idx < n) {
            size_t bstart = idx;
            size_t bend = std::min(n, bstart + chosen_block_size);
            tasks.push_back(pool->enqueue([bstart, bend, &lut_share]() {
                for (size_t j = bstart; j < bend; ++j) lut_share[j].set_message(0);
            }));
            idx = bend;
        }
    }
    for (auto &f : tasks) f.get();
    tasks.clear();
}

template <typename IO>
ELGL_PK LVT<IO>::DistKeyGen(bool offline) {
    // first broadcast my own pk
    vector<std::future<void>> tasks;
    global_pk = elgl->kp.get_pk();
    elgl->serialize_sendall(global_pk);
    for (size_t i = 1; i <= num_party; i++){
        if (i != party){
            tasks.push_back(pool->enqueue([this, i](){
                // rcv other's pk
                ELGL_PK pk;
                elgl->deserialize_recv(pk, i);
                this->user_pk[i-1] = pk;
            }));
        }
    }
    for (auto & task : tasks) {
        task.get();
    }
    tasks.clear();
    // cal global pk_
    BLS12381Element global_pk_ = BLS12381Element(0);
    for (auto& pk : user_pk){
        global_pk_ += pk.get_pk();
    }
    global_pk.assign_pk(global_pk_);
    Ciphertext tmp; tmp.set(global_pk.get_pk(), global_pk.get_pk());
    elgl->serialize_sendall(tmp);
    for (size_t i = 1; i <= num_party; i++){
        Ciphertext tmp_; 
        if (i!= party){
            elgl->deserialize_recv(tmp_, i);
            if (tmp != tmp_){
                std::cerr << "[Error] global_pk_ not equal to sum of other's pk!" << std::endl;
                exit(1);
            }
        }
    }
    return global_pk;
}

template <typename IO>
Fr thdcp(Ciphertext& c, ELGL<IO>* elgl, const ELGL_PK& global_pk, const std::vector<ELGL_PK>& user_pks, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, std::map<std::string, Fr>& P_to_m, LVT<IO>* lvt) {
    Plaintext sk(elgl->kp.get_sk().get_sk());
    BLS12381Element ask = c.get_c0() * sk.get_message();
    std::vector<BLS12381Element> ask_parts(num_party);
    ask_parts[party - 1] = ask;

    ExpProof exp_proof(global_pk);
    ExpProver exp_prover(exp_proof);
    ExpVerifier exp_verifier(exp_proof);

    std::stringstream commit, response;
    BLS12381Element g1 = c.get_c0();
    BLS12381Element y1 = user_pks[party-1].get_pk();
    exp_prover.NIZKPoK(exp_proof, commit, response, g1, y1, ask, sk, party, pool);

    std::stringstream commit_b64, response_b64;
    commit_b64 << base64_encode(commit.str());
    response_b64 << base64_encode(response.str());

    elgl->serialize_sendall_(commit_b64);
    elgl->serialize_sendall_(response_b64);
    std::vector<std::future<void>> verify_futures;
    for (int i = 1; i <= num_party; ++i) {
        if (i != party) {
            verify_futures.push_back(pool->enqueue([i, &party, global_pk, elgl, &ask_parts, &g1, &user_pks, pool]() {
                ExpProof exp_proof(global_pk);
                std::stringstream local_commit_stream, local_response_stream;

                elgl->deserialize_recv_(local_commit_stream, i);
                elgl->deserialize_recv_(local_response_stream, i);

                std::string comm_raw = local_commit_stream.str();
                std::string resp_raw = local_response_stream.str();

                local_commit_stream.str("");
                local_commit_stream.clear();
                local_commit_stream << base64_decode(comm_raw);
                local_commit_stream.seekg(0);

                local_response_stream.str("");
                local_response_stream.clear();
                local_response_stream << base64_decode(resp_raw);
                local_response_stream.seekg(0);

                BLS12381Element y1_other = user_pks[i - 1].get_pk();
                BLS12381Element ask_i;
                ExpVerifier exp_verifier(exp_proof);
                exp_verifier.NIZKPoK(g1, y1_other, ask_i, local_commit_stream, local_response_stream, pool, i);
                ask_parts[i - 1] = ask_i;
            }));
        }
    }
    for (auto& fut : verify_futures) fut.get();
    verify_futures.clear();


    BLS12381Element pi_ask = c.get_c1();
    for (auto& ask_i : ask_parts) {
        pi_ask -= ask_i;
    }

    std::string key = pi_ask.getPoint().getStr();
    Fr y;
    if(lvt->ad <= 131072) {
        auto it = P_to_m.find(key);
        bool t = 1;
        if (it == P_to_m.end()) {
            t = 0;
        }
        if (t) return it->second;
    } 
    cout << "lvt->bsgs.solve_parallel_with_pool" << endl;
    y = lvt->bsgs.solve_parallel_with_pool(pi_ask, pool, thread_num);
    cout << "lvt->bsgs.solve_parallel_with_pool end" << endl;
    return y;
}


template <typename IO>
BLS12381Element thdcp_(Ciphertext& c, ELGL<IO>* elgl, const ELGL_PK& global_pk, const std::vector<ELGL_PK>& user_pks, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, std::map<std::string, Fr>& P_to_m, LVT<IO>* lvt) {
    Plaintext sk(elgl->kp.get_sk().get_sk());
    BLS12381Element ask = c.get_c0() * sk.get_message();
    std::vector<BLS12381Element> ask_parts(num_party);
    ask_parts[party - 1] = ask;

    ExpProof exp_proof(global_pk);
    ExpProver exp_prover(exp_proof);
    ExpVerifier exp_verifier(exp_proof);

    std::stringstream commit, response;
    BLS12381Element g1 = c.get_c0();
    BLS12381Element y1 = user_pks[party-1].get_pk();
    exp_prover.NIZKPoK(exp_proof, commit, response, g1, y1, ask, sk, party, pool);

    std::stringstream commit_b64, response_b64;
    commit_b64 << base64_encode(commit.str());
    response_b64 << base64_encode(response.str());

    elgl->serialize_sendall_(commit_b64);
    elgl->serialize_sendall_(response_b64);

    std::vector<std::future<void>> verify_futures;
    for (int i = 1; i <= num_party; ++i) {
        if (i != party) {
            verify_futures.push_back(pool->enqueue([i, &party, global_pk, elgl, &ask_parts, &g1, &user_pks, pool]() {
                ExpProof exp_proof(global_pk);
                std::stringstream local_commit_stream, local_response_stream;

                elgl->deserialize_recv_(local_commit_stream, i);
                elgl->deserialize_recv_(local_response_stream, i);

                std::string comm_raw = local_commit_stream.str();
                std::string resp_raw = local_response_stream.str();

                local_commit_stream.str("");
                local_commit_stream.clear();
                local_commit_stream << base64_decode(comm_raw);
                local_commit_stream.seekg(0);

                local_response_stream.str("");
                local_response_stream.clear();
                local_response_stream << base64_decode(resp_raw);
                local_response_stream.seekg(0);

                BLS12381Element y1_other = user_pks[i - 1].get_pk();
                BLS12381Element ask_i;
                ExpVerifier exp_verifier(exp_proof);
                exp_verifier.NIZKPoK(g1, y1_other, ask_i, local_commit_stream, local_response_stream, pool, i);
                ask_parts[i - 1] = ask_i;
            }));
        }
    }
    for (auto& fut : verify_futures) fut.get();
    verify_futures.clear();


    BLS12381Element pi_ask = c.get_c1();
    for (auto& ask_i : ask_parts) {
        pi_ask -= ask_i;
    }

    return pi_ask;
}

template <typename IO>
Plaintext LVT<IO>::lookup_online(Plaintext& x_share){ 
    auto start = clock_start();
    int bytes_start = io->get_total_bytes_sent();

    Plaintext out;
    vector<std::future<void>> res;
    vector<Plaintext> u_shares;

    u_shares.resize(num_party);
    u_shares[party-1] = x_share + this->rotation;

    for (size_t i = 1; i <= num_party; i++){
        res.push_back(pool->enqueue([this, i, &u_shares](){
            if (i != party){
                Plaintext u_share;
                elgl->deserialize_recv(u_share, i);
                u_shares[i-1] = u_share;
            }
        }));
    }
    elgl->serialize_sendall(u_shares[party-1], party);
    for (auto& v : res)
        v.get();
    res.clear();

    Plaintext uu = u_shares[0];
    for (size_t i=1; i<num_party; i++){
        uu += u_shares[i];
    }
    mcl::Vint h;
    h.setStr(to_string(su));
    mcl::Vint q1 = uu.get_message().getMpz();
    mcl::gmp::mod(q1, q1, h);
    uu.assign(q1.getStr());

    mcl::Vint tbs;
    tbs.setStr(to_string(su));
    mcl::Vint u_mpz = uu.get_message().getMpz(); 
    mcl::gmp::mod(u_mpz, u_mpz, tbs);

    mcl::Vint index_mpz;
    index_mpz.setStr(u_mpz.getStr());
    size_t index = static_cast<size_t>(index_mpz.getLow32bit());

    out = this->lut_share[index];
    
    int bytes_end = io->get_total_bytes_sent();
    double comm_mb = double(bytes_end - bytes_start) / 1024.0 / 1024.0;
    std::cout << "Online time: " << std::fixed << std::setprecision(6) << time_from(start) / 1e6 << " seconds, " << std::fixed << std::setprecision(6) << "Online communication: " << comm_mb << " MB" << std::endl;

    return out;
}

template <typename IO>
vector<Plaintext>
LVT<IO>::lookup_online_batch(vector<Plaintext>& x_share)
{
    const size_t x_size = x_share.size();
    vector<Plaintext> out(x_size);
    vector<Plaintext> uu(x_size);
    if (x_size == 0) return out;

    const size_t T = pool->size();
    const size_t chunk = (x_size + T - 1) / T;

    {
        vector<future<void>> futs;
        futs.reserve(T);

        for (size_t t = 0; t < T; ++t) {
            size_t l = t * chunk;
            size_t r = std::min(l + chunk, x_size);
            if (l >= r) break;

            futs.emplace_back(
                pool->enqueue([&, l, r]() {
                    for (size_t i = l; i < r; ++i)
                        uu[i] = x_share[i] + rotation;
                })
            );
        }
        for (auto& f : futs) f.get();
    }

    std::stringstream send_ss;
    for (size_t i = 0; i < x_size; ++i)
        uu[i].pack(send_ss);

    elgl->serialize_sendall_(send_ss);

    vector<vector<Plaintext>> recv_results(num_party);

    vector<future<void>> recv_futs;
    for (int p = 1; p <= num_party; ++p) {
        if (p == party) continue;

        recv_futs.emplace_back(
            pool->enqueue([&, p]() {
                std::stringstream recv_ss;
                elgl->deserialize_recv_(recv_ss, p);
                auto& tmp = recv_results[p - 1];
                tmp.resize(x_size);
                for (size_t i = 0; i < x_size; ++i)
                    tmp[i].unpack(recv_ss);
            })
        );
    }
    for (auto& f : recv_futs) f.get();

    {
        vector<future<void>> futs;
        futs.reserve(T);

        for (size_t t = 0; t < T; ++t) {
            size_t l = t * chunk;
            size_t r = std::min(l + chunk, x_size);
            if (l >= r) break;

            futs.emplace_back(
                pool->enqueue([&, l, r]() {
                    for (size_t i = l; i < r; ++i) {
                        for (int p = 0; p < num_party; ++p) {
                            if (p == party - 1) continue;
                            uu[i] += recv_results[p][i];
                        }
                    }
                })
            );
        }
        for (auto& f : futs) f.get();
    }

    mcl::Vint tbs;
    tbs.setStr(to_string(su));

    {
        vector<future<void>> futs;
        futs.reserve(T);

        for (size_t t = 0; t < T; ++t) {
            size_t l = t * chunk;
            size_t r = std::min(l + chunk, x_size);
            if (l >= r) break;

            futs.emplace_back(
                pool->enqueue([&, l, r]() {
                    for (size_t i = l; i < r; ++i) {
                        mcl::Vint u_mpz = uu[i].get_message().getMpz();
                        mcl::gmp::mod(u_mpz, u_mpz, tbs);

                        size_t index =
                            static_cast<size_t>(u_mpz.getLow32bit());
                        out[i] = lut_share[index];
                    }
                })
            );
        }
        for (auto& f : futs) f.get();
    }

    return out;
}


template <typename IO>
LVT<IO>::~LVT(){
}


}

void serializeTable(vector<int64_t>& table, const char* filename, size_t table_size = 1<<16) {
    if (table.size() > table_size) {
        cerr << "Error: Table size exceeds the given limit.\n";
        return;
    }

    ofstream outFile(filename, ios::binary);
    if (!outFile) {
        cerr << "Error: Unable to open file for writing.\n";
        return;
    }

    outFile.write(reinterpret_cast<const char*>(table.data()), table.size() * sizeof(int64_t));
    outFile.close();
}

Fr alpha_init(int num) {
    Plaintext alpha;
    const mcl::Vint p("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    const mcl::Vint g("5");
    mcl::Vint su = mcl::Vint(1) << num;
    mcl::Vint alpha_vint;
    mcl::gmp::powMod(alpha_vint, g, (p - 1) / su, p);
    alpha.assign(alpha_vint.getStr());
    return alpha.get_message();
}