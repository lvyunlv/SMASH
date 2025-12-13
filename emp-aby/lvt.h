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

void deserializeTable(vector<int64_t>& table, const char* filename, size_t se = 1<<16) {
    ifstream inFile(filename, ios::binary);
    if (!inFile) {
        cerr << "Error: Unable to open file for reading.\n Error in 'file: " << filename << "'.";
        exit(1);
    }

    table.resize(se);  // 预分配空间
    inFile.read(reinterpret_cast<char*>(table.data()), se * sizeof(int64_t));

    // 计算实际读取的元素个数
    size_t elementsRead = inFile.gcount() / sizeof(int64_t);
    table.resize(elementsRead);  // 调整大小以匹配实际读取的内容

    inFile.close();
}


void halfpack(BLS12381Element G1, std::stringstream& os) {
    uint8_t buf[256]; // 足够容纳 ETH 序列化的 G1/G2
    cybozu::MemoryOutputStream mos(buf, sizeof(buf));

    bool ok;
    G1.point.save(&ok, mos, mcl::IoSerialize);  // 二进制序列化
    if (!ok) {
        throw std::runtime_error("BLS12381Element::pack serialize failed");
    }

    uint32_t len = mos.getPos();     // 实际写入字节数
    os.write((char*)&len, sizeof(uint32_t));
    os.write((char*)buf, len);
}

void halfunpack(BLS12381Element G1, std::stringstream& is) {
    uint32_t len;
    is.read((char*)&len, sizeof(uint32_t));

    if (len == 0 || len > 256) {
        throw std::runtime_error("BLS12381Element::unpack invalid length");
    }

    uint8_t buf[256];
    is.read((char*)buf, len);

    cybozu::MemoryInputStream mis(buf, len);
    bool ok;
    G1.point.load(&ok, mis, mcl::IoSerialize);   // 二进制反序列化
    if (!ok) {
        throw std::runtime_error("BLS12381Element::unpack load failed");
    }
}

Plaintext set_challenge(const std::stringstream& ciphertexts) {
    Plaintext challenge;
    auto* buf = ciphertexts.rdbuf();
    std::streampos size = buf->pubseekoff(0, ciphertexts.end, ciphertexts.in);
    buf->pubseekpos(0, ciphertexts.in);
    char* tmp = new char[size];
    buf->sgetn(tmp, size);
    challenge.setHashof(tmp, size);
    delete[] tmp;
    return challenge;
}

template <typename IO>
class LVT{
    public:
    int num_used = 0;
    ThreadPool* pool;
    BLS12381Element G_tbs;

    ELGL<IO>* elgl;
    MPIOChannel<IO>* io;
    std::vector<Ciphertext> cr_i;
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
    BLS12381Element g = BLS12381Element::generator();
    
    int num_party;
    int party;
    vector<int64_t> table;
    LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha, int se, int da);
    LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, std::string tableFile, Fr& alpha, int se, int da);
    static void initialize(std::string name, LVT<IO>*& lvt_ptr_ref, int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha_fr, int se, int da);
    static void initialize_batch(std::string name, LVT<IO>*& lvt_ptr_ref, int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha_fr, int se, int da);
    ELGL_PK DistKeyGen(bool offline);
    ~LVT();
    void generate_shares(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table);
    void generate_shares_(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table);
    void generate_shares_fake(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table);
    tuple<Plaintext, vector<Ciphertext>> lookup_online(Plaintext& x_share, vector<Ciphertext>& x_cipher);
    tuple<Plaintext, vector<Ciphertext>> lookup_online_(Plaintext& x_share, Ciphertext& x_cipher, vector<Ciphertext>& x_ciphers);
    tuple<vector<Plaintext>, vector<vector<Ciphertext>>> lookup_online_batch(vector<Plaintext>& x_share, vector<vector<Ciphertext>>& x_cipher); 
    tuple<vector<Plaintext>, vector<vector<Ciphertext>>> lookup_online_batch(vector<Plaintext>& x_share, vector<Ciphertext>& x_cipher); 
    vector<Plaintext> lookup_online_batch_(vector<Plaintext>& x_share);
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
    
    size_t se = table.size();
    memcpy(ptr, &se, sizeof(size_t)); ptr += sizeof(size_t);
    memcpy(ptr, table.data(), se * sizeof(int64_t)); ptr += se * sizeof(int64_t);
    
    for (int i = 0; i < num_party; ++i) {
        for (size_t j = 0; j < su; ++j) {
            const G1& point = cip_lut[i][j].getPoint();
            memcpy(ptr, &point, sizeof(G1)); ptr += sizeof(G1);
        }
    }
    
    for (int i = 0; i < num_party; ++i) {
        const G1& c0 = cr_i[i].get_c0().getPoint();
        const G1& c1 = cr_i[i].get_c1().getPoint();
        memcpy(ptr, &c0, sizeof(G1)); ptr += sizeof(G1);
        memcpy(ptr, &c1, sizeof(G1)); ptr += sizeof(G1);
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
    
    size_t se;
    memcpy(&se, ptr, sizeof(size_t)); ptr += sizeof(size_t);
    table.resize(se);
    memcpy(table.data(), ptr, se * sizeof(int64_t)); ptr += se * sizeof(int64_t);

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
    
    cr_i.resize(num_party);
    for (int i = 0; i < num_party; ++i) {
        G1 c0, c1;
        memcpy(&c0, ptr, sizeof(G1)); ptr += sizeof(G1);
        memcpy(&c1, ptr, sizeof(G1)); ptr += sizeof(G1);
        
        BLS12381Element e0, e1;
        e0.point = c0;
        e1.point = c1;
        cr_i[i] = Ciphertext(e0, e1);
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
LVT<IO>::LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha, int se, int da){
    this->io = io;
    this->party = party;
    this->num_party = num_party;
    this->alpha = alpha;
    this->pool = pool;
    this->elgl = elgl;
    this->user_pk.resize(num_party);
    this->user_pk[party-1] = elgl->kp.get_pk();
    this->su = 1ULL << se;
    this->ad = 1ULL << da;
    this->cip_lut.resize(num_party);
    this->cr_i.resize(num_party);
    this->lut_share.resize(su);
    this->G_tbs = BLS12381Element(su);
    BLS12381Element::init();
    BLS12381Element g = BLS12381Element::generator();
    this->global_pk = DistKeyGen(1);
}

template <typename IO>
void LVT<IO>::initialize(std::string func_name, LVT<IO>*& lvt_ptr_ref, int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha_fr, int se, int da) {
    std::string full_state_path = "../cache/lvt_" + func_name + "_size" + std::to_string(se) + "-P" + std::to_string(party) + ".bin";
    fs::create_directories("../cache");
    lvt_ptr_ref = new LVT<IO>(num_party, party, io, pool, elgl, func_name, alpha_fr, se, da);
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
void LVT<IO>::initialize_batch(std::string func_name, LVT<IO>*& lvt_ptr_ref, int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, Fr& alpha_fr, int se, int da) {
    // std::string full_state_path = "../cache/lvt_batch_" + func_name + "_size" + std::to_string(se) + "-P" + std::to_string(party) + ".bin";
    // fs::create_directories("../cache");
    lvt_ptr_ref = new LVT<IO>(num_party, party, io, pool, elgl, func_name, alpha_fr, se, da);
    // if (fs::exists(full_state_path)) {
    //     auto start = clock_start();
    //     lvt_ptr_ref->load_full_state(full_state_path);
    //     std::cout << "Loading cached state time: " << std::fixed << std::setprecision(6) << time_from(start) / 1e6 << " seconds" << std::endl;
    // } else {
        auto start = clock_start();
        cout << "Generating new state..." << endl;
        lvt_ptr_ref->generate_shares_(lvt_ptr_ref->lut_share, lvt_ptr_ref->rotation, lvt_ptr_ref->table);
        cout << "Generate shares finished" << endl;
        // lvt_ptr_ref->save_full_state(full_state_path);
        // std::cout << "Generate and cache state time: " << std::fixed << std::setprecision(6) << time_from(start) / 1e6 << " seconds" << std::endl;
    // }
}

template <typename IO>
LVT<IO>::LVT(int num_party, int party, MPIOChannel<IO>* io, ThreadPool* pool, ELGL<IO>* elgl, string func_name, Fr& alpha, int se, int da)
    : LVT(num_party, party, io, pool, elgl, alpha, se, da) {
    fs::create_directories("../cache");
    std::string tableFile = "../bin/table_" + func_name + ".txt";
    std::string table_cache = "../cache/table_" + func_name + "_" + std::to_string(se) + ".bin";
    std::string p_to_m_cache = "../cache/p_to_m_" + std::to_string(da) + ".bin";
    std::string bsgs_cache = "../cache/bsgs_40.bin";
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
    if (2 * su * num_party <= 256) {
        build_safe_P_to_m(P_to_m, 2 * su * num_party);
        return;
    }
    // if (da <= 16) {
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
            bsgs.precompute(BLS12381Element::generator(), N);
            bsgs.serialize(bsgs_cache.c_str());
        }
    } else {
        bsgs.precompute(BLS12381Element::generator(), N);
        bsgs.serialize(bsgs_cache.c_str());
    }
}

template <typename IO>
void LVT<IO>::generate_shares(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table) {
    vector<std::future<void>> res;
    vector<BLS12381Element> c0(su);
    vector<BLS12381Element> c1(su);
    vector<BLS12381Element> c0_(su);
    vector<BLS12381Element> c1_(su);
    RotationProof rot_proof(global_pk, global_pk, su);
    RotationVerifier Rot_verifier(rot_proof);
    RotationProver Rot_prover(rot_proof);
    mcl::Vint bound; bound.setStr(to_string(su));
    RangeProof Range_proof(global_pk, bound, su);
    RangeVerifier Range_verifier(Range_proof);
    RangeProver Range_prover(Range_proof);
    ELGL_SK sbsk, twosk; rotation.set_random(bound);
    Ciphertext my_rot_cipher = global_pk.encrypt(rotation);
    elgl->serialize_sendall(my_rot_cipher);
    for (int i = 1; i <= num_party; ++i) {
        res.emplace_back(pool->enqueue([this, &my_rot_cipher, i]() {
            if (i == party){
                this->cr_i[party-1] = my_rot_cipher;
            }else{
                Ciphertext other_rot_cipher;
                elgl->deserialize_recv(other_rot_cipher, i);
                this->cr_i[i-1] = other_rot_cipher;
            }
        }));
    }
    for (auto & f : res) f.get();
    res.clear();
    auto write_block = [&](std::stringstream &ss, const std::string &s) {
        uint32_t len = s.size();
        ss.write((char*)&len, sizeof(len));
        ss.write(s.data(), len);
    };
    auto read_block = [&](std::stringstream &ss, std::string &s) {
        uint32_t len;
        ss.read((char*)&len, sizeof(len));
        s.resize(len);
        ss.read(&s[0], len);
    };
    if (party == ALICE) {
        std::stringstream comm, response, encMap;
        elgl->DecProof(global_pk, comm, response, encMap, this->table, su, c0, c1, pool);
        std::string comm_b64 = base64_encode(comm.str());
        std::string response_b64 = base64_encode(response.str());
        std::string encMap_b64 = base64_encode(encMap.str());
        std::stringstream packet;
        write_block(packet, response_b64);
        write_block(packet, comm_b64);
        write_block(packet, encMap_b64);
        elgl->serialize_sendall_(packet);  
    }
    else {
        std::stringstream packet;
        elgl->deserialize_recv_(packet, ALICE); 
        std::string response_b64, comm_b64, encMap_b64;
        read_block(packet, response_b64);
        read_block(packet, comm_b64);
        read_block(packet, encMap_b64);
        std::stringstream response_dec, comm_dec, encMap_dec;
        response_dec << base64_decode(response_b64);
        comm_dec << base64_decode(comm_b64);
        encMap_dec << base64_decode(encMap_b64);
        elgl->DecVerify(global_pk, comm_dec, response_dec, encMap_dec, c0, c1, su, pool);
    }
    vector<BLS12381Element> ak;
    vector<BLS12381Element> bk;
    vector<BLS12381Element> dk;
    vector<BLS12381Element> ek;
    ak.resize(su);
    bk.resize(su);
    dk.resize(su);
    ek.resize(su);
    mcl::Unit N(su);
    res.push_back(pool->enqueue(
        [this, &c0, &ak, N](){
            FFT_Para(c0, ak, this->alpha, N);     
        }
    ));
    res.push_back(pool->enqueue(
        [this, &c1, &bk, N](){
            FFT_Para(c1, bk, this->alpha, N);
        }
    ));
    for (auto& f : res) f.get();
    res.clear();
    if (party == ALICE)
    {
        Plaintext beta;
        vector<Plaintext> betak(su);
        Plaintext::pow(beta, alpha, rotation);
        vector<Plaintext> sk(su);
        sk[0].set_random();
        std::fill(sk.begin(), sk.begin() + su, sk[0]);
        BLS12381Element dkk = BLS12381Element(1) * sk[0].get_message();
        BLS12381Element ekk = global_pk.get_pk() * sk[0].get_message();
        for (size_t i = 0; i < su; i++){
            res.push_back(pool->enqueue(
                [this, i, &dk, &ek, &sk, &ak, &bk, &beta, &dkk, &ekk](){
                    Plaintext betak_;
                    Plaintext i_;
                    i_.assign(to_string(i));
                    Plaintext::pow(betak_, beta, i_);
                    dk[i] = dkk + ak[i] * betak_.get_message();
                    ek[i] = ekk + bk[i] * betak_.get_message();
                }
            ));
        }
        for (auto& f : res) f.get();
        res.clear();
        std::stringstream commit_ro, response_ro;
        Rot_prover.NIZKPoK(rot_proof, commit_ro, response_ro, global_pk, global_pk, dk, ek, ak, bk, beta, sk, pool);
        std::stringstream comm_ro_, response_ro_;        
        std::string comm_raw = commit_ro.str();
        comm_ro_ << base64_encode(comm_raw);
        std::string response_raw = response_ro.str();
        response_ro_ << base64_encode(response_raw);
        elgl->serialize_sendall_(comm_ro_);
        elgl->serialize_sendall_(response_ro_);
    }
    
    for (size_t i = 1; i <= num_party -1; i++){
        size_t index = i - 1;
        if (i == party) {
            continue;
        }else{
            res.push_back(pool->enqueue([this, i, index, &c0, &c1, &dk, &ek, &Rot_prover,&rot_proof, &Rot_verifier, &rotation]()
            {
                vector<BLS12381Element> ak_thread(su);
                vector<BLS12381Element> bk_thread(su);
                vector<BLS12381Element> dk_thread(su);
                vector<BLS12381Element> ek_thread(su);
                std::stringstream comm_ro, response_ro;
                std::string comm_raw, response_raw;
                std::stringstream comm_, response_;
                elgl->deserialize_recv_(comm_ro, i);
                elgl->deserialize_recv_(response_ro, i);
                comm_raw = comm_ro.str();
                response_raw = response_ro.str();
                comm_ << base64_decode(comm_raw);
                response_ << base64_decode(response_raw);
                Rot_verifier.NIZKPoK(dk_thread, ek_thread, ak_thread, bk_thread, comm_, response_, this->global_pk, this->global_pk, pool);
                if (i == this->party - 1) {
                    vector<BLS12381Element> dk_(su);
                    vector<BLS12381Element> ek_(su);
                    Plaintext beta;
                    Plaintext::pow(beta, alpha, rotation);
                    vector<Plaintext> sk(su);
                    vector<std::future<void>> res_;
                    sk[0].set_random();
                    std::fill(sk.begin(), sk.begin() + su, sk[0]);
                    BLS12381Element dkk = BLS12381Element(1) * sk[0].get_message();
                    BLS12381Element ekk = global_pk.get_pk() * sk[0].get_message();
                    for (size_t i = 0; i < su; i++){
                        res_.push_back(pool->enqueue(
                            [this, i, &dk_, &ek_, &sk, &ak_thread, &bk_thread, &dk_thread, &ek_thread, &beta, &dkk, &ekk]()
                            {
                                Plaintext betak;
                                Plaintext i_;
                                i_.assign(to_string(i));
                                Plaintext::pow(betak, beta, i_);
                                dk_[i] = dkk + dk_thread[i] * betak.get_message();
                                ek_[i] = ekk + ek_thread[i] * betak.get_message();
                            }
                        ));
                    }
                    for (auto & f : res_) {
                        f.get();
                    }
                    res_.clear();
                    std::stringstream commit_ro, response_ro;
                    Rot_prover.NIZKPoK(rot_proof, commit_ro, response_ro, 
                    global_pk, global_pk, dk_, ek_, dk_thread, ek_thread, beta, sk, pool);
                    std::stringstream comm_ro_final, response_ro_final; 
                    std::string comm_raw_final, response_raw_final;
                    comm_raw_final = commit_ro.str();
                    response_raw_final = response_ro.str();
                    comm_ro_final << base64_encode(comm_raw_final);
                    response_ro_final << base64_encode(response_raw_final);
                    elgl->serialize_sendall_(comm_ro_final);
                    elgl->serialize_sendall_(response_ro_final);
                    if (this->num_party == this->party){
                        dk = dk_;
                        ek = ek_;
                    }
                }
            }));
        }
    }
    for (auto& v : res) v.get();
    res.clear();

    if (party != num_party){
        std::stringstream comm_ro, response_ro;
        std::string comm_raw, response_raw;
        std::stringstream comm_, response_;
        elgl->deserialize_recv_(comm_ro, num_party);
        elgl->deserialize_recv_(response_ro, num_party);
        comm_raw = comm_ro.str();
        response_raw = response_ro.str();
        comm_ << base64_decode(comm_raw);
        response_ << base64_decode(response_raw);
        Rot_verifier.NIZKPoK(dk, ek, ak, bk, comm_, 
        response_, global_pk, global_pk, pool);
    }
    Plaintext alpha_inv;
    Fr alpha_inv_;
    Fr::inv(alpha_inv_, alpha);
    alpha_inv.assign(alpha_inv_.getMpz());
    Fr N_inv;
    Fr::inv(N_inv, N);
    res.push_back(pool->enqueue(
        [this, &dk, &c0_, &N, &alpha_inv]()
        {
            FFT_Para(dk, c0_, alpha_inv.get_message(), N);
        }
    ));
    res.push_back(pool->enqueue(
        [this, &ek, &c1_, &N, &alpha_inv]()
        {
            FFT_Para(ek, c1_, alpha_inv.get_message(), N);
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
            std::stringstream commit_ro, response_ro;
            std::string comm_raw, response_raw;
            std::stringstream comm_, response_;
            elgl->deserialize_recv_(commit_ro, i);
            elgl->deserialize_recv_(response_ro, i);
            comm_raw = commit_ro.str();
            response_raw = response_ro.str();
            comm_ << base64_decode(comm_raw);
            response_ << base64_decode(response_raw);
            BLS12381Element pk__ = user_pk[i-1].get_pk();
            Range_verifier.NIZKPoK(pk__, y3, y2, comm_, response_, c0_, global_pk, pool);
            vector<std::future<void>> res_;
            for (size_t j = 0; j < su; j++) {
                res_.push_back(pool->enqueue([&l_alice, &y2, j]() {
                    l_alice[j] -= y2[j];
                }));
            }
            for (auto& f : res_) {
                f.get();
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
        if(flag){
            BLS12381Element pk_tmp = this->global_pk.get_pk() * this->elgl->kp.get_sk().get_sk();
            for (size_t i = 0; i < su; i++){
                res.push_back(pool->enqueue([this, &l_alice, &c0_, &lut_share, &L, i, &pk_tmp]() {
                    BLS12381Element Y = l_alice[i] - c0_[i] * elgl->kp.get_sk().get_sk(); Fr y; 
                    auto it = this->P_to_m.find(Y.getPoint().getStr());
                    if (it == this->P_to_m.end()) {
                        std::cerr << "[Error] y not found in P_to_m! y = " << Y.getPoint().getStr() << std::endl;
                        exit(1);
                    } else {
                        y = it->second;
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
                    this->cip_lut[0][i] = BLS12381Element(r) + pk_tmp;
                }));
            }
            for (auto& f : res) f.get();
            res.clear();
        } else {
            vector<BLS12381Element> Ys(su);
            for (size_t i = 0; i < su; i++){
                res.push_back(pool->enqueue([this, &l_alice, &c0_, &lut_share, &L, i, &Ys]() {
                    Ys[i] = l_alice[i] - c0_[i] * elgl->kp.get_sk().get_sk(); 
                }));
            }
            for (auto& f : res) f.get();
            res.clear();
            vector<int64_t> ys = this->bsgs.solve_parallel_with_pool_vector(Ys, this->pool, thread_num);
            BLS12381Element pk_tmp = this->global_pk.get_pk() * this->elgl->kp.get_sk().get_sk();
            for (size_t i = 0; i < su; i++){
                res.push_back(pool->enqueue([this, &l_alice, &c0_, &lut_share, &L, i, &ys, &pk_tmp]() {
                    mcl::Vint r_;
                    int64_t y_i = ys[i];
                    mpz_class y_; y_.setStr(std::to_string(y_i));
                    mcl::Vint ms;  
                    ms.setStr(to_string(this->ad));
                    mcl::gmp::mod(r_, y_, ms);
                    Fr r;
                    r.setMpz(r_);
                    lut_share[i].set_message(r);
                    BLS12381Element l(r);
                    l += c0_[i] * this->elgl->kp.get_sk().get_sk();
                    L[i] = BLS12381Element(l);
                    this->cip_lut[0][i] = BLS12381Element(r) + pk_tmp;
                }));
            }
            for (auto& f : res) f.get();
            res.clear();
        }
        std::stringstream commit_ss, response_ss;
        std::string commit_raw, response_raw;
        std::stringstream commit_b64_, response_b64_;
        Range_prover.NIZKPoK(Range_proof, commit_ss, response_ss, global_pk, c0_, cip_lut[0], L, lut_share, elgl->kp.get_sk().get_sk(), pool);
        commit_raw = commit_ss.str();
        commit_b64_ << base64_encode(commit_raw);
        response_raw = response_ss.str();
        response_b64_ << base64_encode(response_raw);
        elgl->serialize_sendall_(commit_b64_);
        elgl->serialize_sendall_(response_b64_);
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
        std::stringstream response_ss;
        vector<BLS12381Element> l_1_v;
        vector<BLS12381Element> cip_v;
        l_1_v.resize(su);
        cip_v.resize(su);
        for (size_t i = 0; i < su; i++) {
             res.push_back(pool->enqueue([this, &c0_, &lut_share, &bound, i, &cip_v, &l_1_v]() {
                lut_share[i].set_random(bound);
                BLS12381Element l_1, cip_;
                l_1 = BLS12381Element(lut_share[i].get_message());
                cip_ = l_1;
                l_1 += c0_[i] * this->elgl->kp.get_sk().get_sk();
                l_1_v[i] = l_1;  
                cip_ += this->global_pk.get_pk() * this->elgl->kp.get_sk().get_sk();
                cip_v[i] = cip_;  
            }));
        }
        for (auto& f : res) f.get();
        res.clear();
        cip_lut[party-1] = cip_v;
        Range_prover.NIZKPoK(Range_proof, commit_ss, response_ss, global_pk, c0_, cip_v, l_1_v, lut_share, elgl->kp.get_sk().get_sk(), pool);
        std::stringstream commit_ra_, response_ra_;
        std::string commit_raw = commit_ss.str();
        commit_ra_ << base64_encode(commit_raw);
        std::string response_raw = response_ss.str();
        response_ra_ << base64_encode(response_raw);
        elgl->serialize_sendall_(commit_ra_);
        elgl->serialize_sendall_(response_ra_);
        for (size_t i = 2; i <= num_party; i++){
            if (i != party){
                vector<BLS12381Element> y3;
                vector<BLS12381Element> y2;
                y3.resize(su);
                y2.resize(su);
                std::stringstream commit_ro, response_ro;
                std::string comm_raw, response_raw;
                std::stringstream comm_, response_;
                elgl->deserialize_recv_(commit_ro, i);
                elgl->deserialize_recv_(response_ro, i);
                comm_raw = commit_ro.str();
                response_raw = response_ro.str();
                comm_ << base64_decode(comm_raw);
                response_ << base64_decode(response_raw);
                BLS12381Element pk__ = user_pk[i-1].get_pk();
                Range_verifier.NIZKPoK(pk__, y3, y2, comm_, response_, c0_, global_pk, pool);
                cip_lut[i-1] = y3;
            }
        }
        std::stringstream commit_ro, response_ro;
        std::string comm_raw_, response_raw_;
        std::stringstream comm_, response_;
        elgl->deserialize_recv_(commit_ro, ALICE);
        elgl->deserialize_recv_(response_ro, ALICE);
        comm_raw_ = commit_ro.str();
        response_raw_ = response_ro.str();
        comm_ << base64_decode(comm_raw_);
        response_ << base64_decode(response_raw_);
        vector<BLS12381Element> y2;
        vector<BLS12381Element> y3;
        y2.resize(su);
        y3.resize(su);
        BLS12381Element pk__ = user_pk[0].get_pk();
        Range_verifier.NIZKPoK(pk__, y3, y2, comm_, response_, c0_, global_pk, pool);
        cip_lut[0] = y3;
        elgl->send_done(ALICE);
    }
    // // print rotation and party id
    // std::cout << "party: " << party << ";  rotation: " << rotation.get_message().getStr() << std::endl;
    // // print lut_share
    // for (size_t i = 0; i < su; i++){
    //     std::cout << "table[" << i << "]:" << lut_share[i].get_message().getStr() << " " << std::endl;
    // }
}

template <typename IO>
void LVT<IO>::generate_shares_(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table) {
    size_t n = table.size();
    lut_share.resize(su);
    cip_lut.assign(num_party, vector<BLS12381Element>());
    for (int p = 0; p < num_party; ++p) cip_lut[p].resize(su);
    rotation.set_message(0); Fr k=1;
    elgl->kp.sk.assign_sk(k);
    elgl->kp.pk = ELGL_PK(elgl->kp.sk);
    BLS12381Element tmp = BLS12381Element(num_party);
    this->global_pk.assign_pk(tmp);
    for (int p = 0; p < num_party; ++p) user_pk[p].assign_pk(tmp);
    cr_i[party-1] = global_pk.encrypt(rotation);
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
    elgl->serialize_sendall(cr_i[party-1]);
    for (int p = 1; p <= num_party; ++p) {
        if (p != party) elgl->deserialize_recv(cr_i[p-1], p);
    }
}


template <typename IO>
void LVT<IO>::generate_shares_fake(vector<Plaintext>& lut_share, Plaintext& rotation, vector<int64_t> table) {
    lut_share.resize(su);
    cip_lut.resize(num_party, vector<BLS12381Element>(su));
    for (int i = 0; i < num_party; ++i) {
        cip_lut[i].resize(su);
    }
    rotation.set_message(0);
    cr_i[party-1] = global_pk.encrypt(rotation);
    BLS12381Element tmp = BLS12381Element(0);
    vector<future<void>> res;
    size_t block_size = (su + thread_num - 1) / thread_num;
    if (party == 1) {
        for (int t = 0; t < thread_num; ++t) {
        size_t start = t * block_size;
        size_t end = std::min(su, start + block_size);
        res.push_back(pool->enqueue([this, &lut_share, &table, start, end]() {
            for (size_t i = start; i < end; ++i) lut_share[i].set_message(table[i]);
        }));
        }
        for (auto& f : res) f.get();
        res.clear();
    } else{
        for (int t = 0; t < thread_num; ++t) {
        size_t start = t * block_size;
        size_t end = std::min(su, start + block_size);
        res.push_back(pool->enqueue([this, &lut_share, &table, start, end]() {
            for (size_t i = start; i < end; ++i) lut_share[i].set_message(0);
        }));
        }
        for (auto& f : res) f.get();
        res.clear();
    }

    for (int i = 0; i < table.size(); ++i) {
        res.push_back(pool->enqueue([this, &lut_share, &tmp, i, &table]() {
            cip_lut[0][i] = BLS12381Element(table[i]) + tmp;
        }));
    }
    for (auto& f : res) f.get();
    res.clear();

    for (int i = 0; i < table.size(); ++i) {
    res.push_back(pool->enqueue([this, &lut_share, &tmp, i, &table]() {
        for (int p = 1; p < this->num_party; ++p)
            cip_lut[p][i] = tmp;
        }));
    }
    for (auto& f : res) f.get();
    res.clear();
}

template <typename IO>
ELGL_PK LVT<IO>::DistKeyGen(bool offline){
    vector<std::future<void>> tasks;
    global_pk = elgl->kp.get_pk();
    elgl->serialize_sendall(global_pk);
    for (size_t i = 1; i <= num_party; i++){
        if (i != party){
            tasks.push_back(pool->enqueue([this, i](){
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
tuple<Plaintext, vector<Ciphertext>> LVT<IO>::lookup_online(Plaintext& x_share, vector<Ciphertext>& x_cipher){ 
    Plaintext out;
    vector<Ciphertext> out_ciphers;
    vector<std::future<void>> res;
    vector<Plaintext> u_shares;
    u_shares.resize(num_party);
    u_shares[party-1] = x_share + this->rotation;
    Ciphertext c = x_cipher[0] + cr_i[0];
    for (size_t i=1; i<num_party; i++){
        c +=  x_cipher[i] + cr_i[i];
    }
    vector<BLS12381Element> P_shares(num_party);
    P_shares[party-1] = elgl->kp.sk.get_sk() * c.get_c0();
    std::stringstream send_ss;
    P_shares[party-1].pack(send_ss);
    u_shares[party-1].pack(send_ss);
    for (size_t i = 1; i <= num_party; i++){
        res.push_back(pool->enqueue([this, i, &P_shares, &u_shares](){
            if (i != party){
                std::stringstream recv_ss;
                elgl->deserialize_recv_(recv_ss, i);
                P_shares[i-1].unpack(recv_ss);
                u_shares[i-1].unpack(recv_ss);
            }
        }));
    }
    elgl->serialize_sendall_(send_ss);
    for (auto& v : res)
        v.get();
    res.clear();
    Plaintext u = u_shares[0];
    BLS12381Element P_sum = P_shares[0];
    for (size_t i=1; i<num_party; i++){
        u += u_shares[i];
        P_sum += P_shares[i];
    }
    BLS12381Element H = c.get_c1() - P_sum;
    BLS12381Element U = BLS12381Element(u.get_message());
    if (U != H){
        std::cerr << "[Error] LVT lookup_online U != H!" << std::endl;
        exit(1);
    }
    mcl::Vint h;
    h.setStr(to_string(su));
    mcl::Vint q1 = u.get_message().getMpz();
    mcl::gmp::mod(q1, q1, h);
    u.assign(q1.getStr());
    mcl::Vint tbs;
    tbs.setStr(to_string(su));
    mcl::Vint u_mpz = u.get_message().getMpz(); 
    mcl::gmp::mod(u_mpz, u_mpz, tbs);
    mcl::Vint index_mpz;
    index_mpz.setStr(u_mpz.getStr());
    size_t index = static_cast<size_t>(index_mpz.getLow32bit());
    out = this->lut_share[index];
    out_ciphers.resize(num_party);
    for (size_t i = 0; i < num_party; i++){
        Ciphertext tmp(user_pk[i].get_pk(), cip_lut[i][index]);
        out_ciphers[i] = tmp;
    }
    return std::make_tuple(out, out_ciphers);
}

template <typename IO>
tuple<Plaintext, vector<Ciphertext>> LVT<IO>::lookup_online_(Plaintext& x_share, Ciphertext& x_cipher, vector<Ciphertext>& x_ciphers){ 
    auto start = clock_start();
    int bytes_start = io->get_total_bytes_sent();

    Plaintext out;
    vector<Ciphertext> out_ciphers;
    vector<std::future<void>> res;
    vector<Plaintext> u_shares;

    x_ciphers.resize(num_party);
    u_shares.resize(num_party);

    x_ciphers[party-1] = x_cipher;
    u_shares[party-1] = x_share + this->rotation;
    std::stringstream send_ss;
    x_ciphers[party-1].pack(send_ss);
    u_shares[party-1].pack(send_ss);
    for (size_t i = 1; i <= num_party; i++){
        res.push_back(pool->enqueue([this, i, &x_ciphers, &u_shares](){
            if (i != party){
                std::stringstream recv_ss;
                elgl->deserialize_recv_(recv_ss, i);
                Ciphertext x_cip;
                x_cip.unpack(recv_ss);
                Plaintext u_share;
                u_share.unpack(recv_ss);
                x_ciphers[i-1] = x_cip;
                u_shares[i-1] = u_share;
            }
        }));
    }
    elgl->serialize_sendall_(send_ss);
    for (auto& v : res)
        v.get();
    res.clear();

    Ciphertext c = x_ciphers[0] + cr_i[0];
    Plaintext uu = u_shares[0];
    for (size_t i=1; i<num_party; i++){
        c +=  x_ciphers[i] + cr_i[i];
        uu += u_shares[i];
    }
    mcl::Vint h;
    h.setStr(to_string(su));
    mcl::Vint q1 = uu.get_message().getMpz();
    mcl::gmp::mod(q1, q1, h);
    uu.assign(q1.getStr());

    Fr u = thdcp(c, elgl, global_pk, user_pk, elgl->io, pool, party, num_party, P_to_m, this);
    mcl::Vint q2 = u.getMpz(); 
    mcl::gmp::mod(q2, q2, h);
    u.setStr(q2.getStr());
    mcl::Vint tbs;
    tbs.setStr(to_string(su));
    mcl::Vint u_mpz = uu.get_message().getMpz(); 
    mcl::gmp::mod(u_mpz, u_mpz, tbs);

    mcl::Vint index_mpz;
    index_mpz.setStr(u_mpz.getStr());
    size_t index = static_cast<size_t>(index_mpz.getLow32bit());

    out = this->lut_share[index];
    out_ciphers.resize(num_party);
    for (size_t i = 0; i < num_party; i++){
        Ciphertext tmp(user_pk[i].get_pk(), cip_lut[i][index]);
        out_ciphers[i] = tmp;
    }
    // cout << "party: " << party << " index = " << index << endl;

    int bytes_end = io->get_total_bytes_sent();
    double comm_kb = double(bytes_end - bytes_start) / 1024.0;
    // std::cout << "Online time: " << std::fixed << std::setprecision(6) << time_from(start) / 1e6 << " seconds, " << std::fixed << std::setprecision(6) << "Online communication: " << comm_kb << " KB" << std::endl;

    return std::make_tuple(out, out_ciphers);
}

template <typename IO>
tuple<vector<Plaintext>, vector<vector<Ciphertext>>> LVT<IO>::lookup_online_batch(vector<Plaintext>& x_shares, vector<vector<Ciphertext>>& x_ciphers)
{
    size_t x_size = x_shares.size();
    if (x_size == 0) return {};
    vector<Plaintext> out(x_size);
    vector<vector<Ciphertext>> out_ciphers(num_party, vector<Ciphertext>(x_size));
    vector<std::future<void>> fut;  
    fut.reserve(x_size);
    vector<Plaintext>  local_u_share(x_size);
    vector<Plaintext>  u_total(x_size);
    vector<Ciphertext> c_total(x_size);
    vector<BLS12381Element> local_p1(x_size);
    vector<BLS12381Element> p_sum(x_size);
    Fr sk = elgl->kp.sk.get_sk();
    for (size_t i = 0; i < x_size; i++) {
        fut.push_back(pool->enqueue([&, i]() {
            local_u_share[i]  = x_shares[i]  + rotation;
            u_total[i] = local_u_share[i];
            c_total[i] = x_ciphers[0][i] + cr_i[0];
            for (size_t p = 1; p < num_party; p++) {
                c_total[i] += x_ciphers[p][i] + cr_i[p];
            }
            local_p1[i] = c_total[i].get_c0() * sk;
            p_sum[i] = local_p1[i];
        }));
    }
    for (auto &f : fut) f.get();
    fut.clear();
    std::stringstream send_ss;
    for (size_t i = 0; i < x_size; ++i) {
        local_p1[i].pack(send_ss);
        local_u_share[i].pack(send_ss);
    }
    Plaintext com = set_challenge(send_ss);
    vector<Plaintext> com_(num_party);
    elgl->serialize_sendall(com);
    for (int p = 1; p <= num_party; p++) {
        if (p == party) continue;
        fut.push_back(pool->enqueue([&, p]() {
            elgl->deserialize_recv(com_[p-1], p);
        }));
    }
    for (auto &f : fut) f.get();
    fut.clear();
    elgl->serialize_sendall_(send_ss);
    vector<std::stringstream> recv_ss(num_party);
    for (int p = 1; p <= num_party; p++) {
        if (p == party) continue;
        fut.push_back(pool->enqueue([&, p]() {
            elgl->deserialize_recv_(recv_ss[p-1], p);
        }));
    }
    for (auto &f : fut) f.get();
    fut.clear();
    vector<vector<BLS12381Element>> recv_p1(num_party, vector<BLS12381Element>(x_size));
    vector<vector<Plaintext>>  recv_shares(num_party, vector<Plaintext>(x_size));
    for (size_t p = 1; p <= num_party; p++) {
        if (p == party) continue;
        fut.push_back(pool->enqueue([&, p]() {
            std::stringstream ol(recv_ss[p-1].str());
            Plaintext pppp = set_challenge(ol);
            if (com_[p-1].get_message().getMpz() != pppp.get_message().getMpz()) {
                throw std::runtime_error("lookup_online_batch check failed: com_ != set_challenge(recv_ss)");
            }
            for (size_t i = 0; i < x_size; ++i) {
                recv_p1[p-1][i].unpack(recv_ss[p-1]);
                recv_shares[p-1][i].unpack(recv_ss[p-1]);
            }
        }));
    }
    for (auto &f : fut) f.get();
    fut.clear();
    size_t num_workers = std::min(static_cast<size_t>(thread_num), x_size);
    size_t block_size = (x_size + num_workers - 1) / num_workers;
    for (size_t w = 0; w < num_workers; ++w) {
        size_t start = w * block_size;
        size_t end = std::min(x_size, start + block_size);
        if (start >= end) continue;
        fut.push_back(pool->enqueue([&, start, end]() {
            for (size_t i = start; i < end; ++i) {
                for (size_t p = 1; p <= num_party; ++p) {
                    if (p == party) continue;
                    p_sum[i] += recv_p1[p-1][i];
                    u_total[i] += recv_shares[p-1][i];
                }
            }
        }));
    }
    for (auto &f : fut) f.get();
    fut.clear();
    mcl::Vint su_mod;
    su_mod.setStr(to_string(su));
    for (size_t i = 0; i < x_size; i++) {
        fut.push_back(pool->enqueue([&, i]() {
            BLS12381Element H = c_total[i].get_c1() - p_sum[i];
            BLS12381Element U = BLS12381Element(u_total[i].get_message());
            if (H != U) {
                std::cerr << "[Error] lookup_online_batch verify fail at i=" << i << " party=" << party << "\n";
                exit(1);
            }
            mcl::Vint v = u_total[i].get_message().getMpz();
            v %= su_mod;
            u_total[i].assign(v.getStr());
            size_t idx = static_cast<size_t>(v.getLow32bit());
            out[i] = lut_share[idx];
            for (size_t p = 0; p < num_party; p++)
                out_ciphers[p][i] = Ciphertext(user_pk[p].get_pk(), cip_lut[p][idx]);
        }));
    }
    for (auto &f : fut) f.get();
    fut.clear();
    return { out, out_ciphers };
}

template <typename IO>
tuple<vector<Plaintext>, vector<vector<Ciphertext>>> LVT<IO>::lookup_online_batch(vector<Plaintext>& x_shares, vector<Ciphertext>& x_cipher)
{
    size_t x_size = x_shares.size();
    if (x_size == 0) return {};
    vector<vector<Ciphertext>> x_ciphers(num_party, vector<Ciphertext>(x_size));
    vector<std::future<void>> recv_futs;
    std::stringstream sendss;
    for (size_t i = 0; i < x_size; ++i) {
        x_cipher[i].pack(sendss);
    }
    for (size_t p = 1; p <= num_party; p++) {
        if (p == party) continue;
        recv_futs.push_back(pool->enqueue([&, p]() {
            std::stringstream recv_ss;
            elgl->deserialize_recv_(recv_ss, p);
            for (size_t i = 0; i < x_size; ++i) {
                x_ciphers[p-1][i].unpack(recv_ss);
            }
        }));
    }
    elgl->serialize_sendall_(sendss);
    for (auto &f : recv_futs) f.get();
    recv_futs.clear();
    
    vector<Plaintext> out(x_size);
    vector<vector<Ciphertext>> out_ciphers(num_party, vector<Ciphertext>(x_size));
    vector<std::future<void>> fut;  
    fut.reserve(x_size);
    vector<Plaintext>  local_u_share(x_size);
    vector<Plaintext>  u_total(x_size);
    vector<Ciphertext> c_total(x_size);
    vector<BLS12381Element> local_p1(x_size);
    vector<BLS12381Element> p_sum(x_size);
    Fr sk = elgl->kp.sk.get_sk();
    for (size_t i = 0; i < x_size; i++) {
        fut.push_back(pool->enqueue([&, i]() {
            local_u_share[i]  = x_shares[i]  + rotation;
            u_total[i] = local_u_share[i];
            c_total[i] = x_ciphers[0][i] + cr_i[0];
            for (size_t p = 1; p < num_party; p++) {
                c_total[i] += x_ciphers[p][i] + cr_i[p];
            }
            local_p1[i] = c_total[i].get_c0() * sk;
            p_sum[i] = local_p1[i];
        }));
    }
    for (auto &f : fut) f.get();
    fut.clear();

    std::stringstream send_ss;
    for (size_t i = 0; i < x_size; ++i) {
        local_p1[i].pack(send_ss);
        local_u_share[i].pack(send_ss);
    }
    Plaintext com = set_challenge(send_ss);
    vector<Plaintext> com_(num_party);
    elgl->serialize_sendall(com);
    for (int p = 1; p <= num_party; p++) {
        if (p == party) continue;
        fut.push_back(pool->enqueue([&, p]() {
            elgl->deserialize_recv(com_[p-1], p);
        }));
    }
    for (auto &f : fut) f.get();
    fut.clear();
    elgl->serialize_sendall_(send_ss);
    vector<std::stringstream> recv_ss(num_party);
    for (int p = 1; p <= num_party; p++) {
        if (p == party) continue;
        fut.push_back(pool->enqueue([&, p]() {
            elgl->deserialize_recv_(recv_ss[p-1], p);
        }));
    }
    for (auto &f : fut) f.get();
    fut.clear();
    vector<vector<BLS12381Element>> recv_p1(num_party, vector<BLS12381Element>(x_size));
    vector<vector<Plaintext>>  recv_shares(num_party, vector<Plaintext>(x_size));
    for (size_t p = 1; p <= num_party; p++) {
        if (p == party) continue;
        fut.push_back(pool->enqueue([&, p]() {
            std::stringstream ol(recv_ss[p-1].str());
            Plaintext pppp = set_challenge(ol);
            if (com_[p-1].get_message().getMpz() != pppp.get_message().getMpz()) {
                throw std::runtime_error("lookup_online_batch check failed: com_ != set_challenge(recv_ss)");
            }
            for (size_t i = 0; i < x_size; ++i) {
                recv_p1[p-1][i].unpack(recv_ss[p-1]);
                recv_shares[p-1][i].unpack(recv_ss[p-1]);
            }
        }));
    }
    for (auto &f : fut) f.get();
    fut.clear();
    size_t num_workers = std::min(static_cast<size_t>(thread_num), x_size);
    size_t block_size = (x_size + num_workers - 1) / num_workers;
    for (size_t w = 0; w < num_workers; ++w) {
        size_t start = w * block_size;
        size_t end = std::min(x_size, start + block_size);
        if (start >= end) continue;
        fut.push_back(pool->enqueue([&, start, end]() {
            for (size_t i = start; i < end; ++i) {
                for (size_t p = 1; p <= num_party; ++p) {
                    if (p == party) continue;
                    p_sum[i] += recv_p1[p-1][i];
                    u_total[i] += recv_shares[p-1][i];
                }
            }
        }));
    }
    for (auto &f : fut) f.get();
    fut.clear();
    mcl::Vint su_mod;
    su_mod.setStr(to_string(su));
    for (size_t i = 0; i < x_size; i++) {
        fut.push_back(pool->enqueue([&, i]() {
            BLS12381Element H = c_total[i].get_c1() - p_sum[i];
            BLS12381Element U = BLS12381Element(u_total[i].get_message());
            mcl::Vint v = u_total[i].get_message().getMpz();
            v %= su_mod;
            u_total[i].assign(v.getStr());
            size_t idx = static_cast<size_t>(v.getLow32bit());
            out[i] = lut_share[idx];
            for (size_t p = 0; p < num_party; p++)
                out_ciphers[p][i] = Ciphertext(user_pk[p].get_pk(), cip_lut[p][idx]);
        }));
    }
    for (auto &f : fut) f.get();
    fut.clear();
    return { out, out_ciphers };
}


template <typename IO>
vector<Plaintext> LVT<IO>::lookup_online_batch_(vector<Plaintext>& x_share){
    size_t x_size = x_share.size();
    vector<Plaintext> out(x_size);
    vector<Plaintext> uu(x_size);
    if (x_size == 0) return out;
    size_t tnum = std::max<size_t>(1, thread_num);
    size_t block_size = (x_size + tnum - 1) / tnum;
    if (block_size == 0) block_size = 1;
    {
        vector<future<void>> futs;
        for (size_t b = 0; b < x_size; b += block_size) {
            size_t bstart = b;
            size_t bend = std::min(x_size, b + block_size);

            futs.push_back(pool->enqueue([this, bstart, bend, &x_share, &uu]() {
                for (size_t i = bstart; i < bend; ++i)
                    uu[i] = x_share[i] + this->rotation;
            }));
        }
        for (auto &f : futs) f.get();
    }
    std::stringstream send_ss;
    for (size_t i = 0; i < x_size; ++i)
        uu[i].pack(send_ss);
    elgl->serialize_sendall_(send_ss);
    vector<future<vector<Plaintext>>> recv_futs;
    recv_futs.reserve(num_party - 1);
    for (int p = 1; p <= num_party; ++p) {
        if (p == party) continue;
        recv_futs.push_back(pool->enqueue([this, p, x_size]() -> vector<Plaintext> {
            std::stringstream recv_ss;
            elgl->deserialize_recv_(recv_ss, p);
            vector<Plaintext> tmp(x_size);
            for (size_t j = 0; j < x_size; ++j)
                tmp[j].unpack(recv_ss);
            return tmp;
        }));
    }
    vector<vector<Plaintext>> recv_results;
    for (auto &f : recv_futs)
        recv_results.push_back(f.get());
    for (auto &tmp_vec : recv_results) {
        vector<future<void>> futs;
        for (size_t b = 0; b < x_size; b += block_size) {
            size_t bstart = b;
            size_t bend = std::min(x_size, b + block_size);

            futs.push_back(pool->enqueue([bstart, bend, &uu, &tmp_vec]() {
                for (size_t j = bstart; j < bend; ++j)
                    uu[j] += tmp_vec[j];
            }));
        }
        for (auto &f : futs) f.get();
    }
    {
        mcl::Vint tbs; tbs.setStr(to_string(su));
        vector<future<void>> futs;

        for (size_t b = 0; b < x_size; b += block_size) {
            size_t bstart = b;
            size_t bend = std::min(x_size, b + block_size);

            futs.push_back(pool->enqueue([this, bstart, bend, &uu, &out, &tbs]() {
                for (size_t i = bstart; i < bend; ++i) {
                    mcl::Vint u_mpz = uu[i].get_message().getMpz();
                    mcl::gmp::mod(u_mpz, u_mpz, tbs);

                    size_t index = static_cast<size_t>(u_mpz.getLow32bit());
                    out[i] = this->lut_share[index];
                }
            }));
        }
        for (auto &f : futs) f.get();
    }
    return out;
}

template <typename IO>
Plaintext LVT<IO>::Reconstruct(Plaintext input, vector<Ciphertext> input_cips, ELGL<IO>* elgl, const ELGL_PK& global_pk, const std::vector<ELGL_PK>& user_pks, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, mcl::Vint modulo){
    Plaintext out = input;
    Ciphertext out_cip = input_cips[party-1];

    elgl->serialize_sendall(input);

    for (int i = 1; i <= num_party; i++){
        if (party != i) {
            Plaintext tmp;
            elgl->deserialize_recv(tmp, i);
            out += tmp;
            out_cip += input_cips[i-1];
        }
    }
    Fr out_ = thdcp(out_cip, elgl, global_pk, user_pks, io, pool, party, num_party, P_to_m, this); 
    mcl::Vint o = out_.getMpz();
    o %= modulo;

    mcl::Vint o_ = out.get_message().getMpz();
    o_ %= modulo;
    
    if (o_ != o) {
        cout << "o_: " << o_ << endl; 
        cout << "o: " << o << endl;
        error("Reconstruct error");
    }
    out.assign(o_);
    return out;
}

template <typename IO>
Plaintext LVT<IO>::Reconstruct_interact(Plaintext input, Ciphertext input_cip, ELGL<IO>* elgl, const ELGL_PK& global_pk, const std::vector<ELGL_PK>& user_pks, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, mcl::Vint modulo){
    Plaintext out = input;
    Ciphertext out_cip = input_cip;

    elgl->serialize_sendall(input);
    for (int i = 1; i <= num_party; i++){
        if (party != i) {
            Plaintext tmp;
            elgl->deserialize_recv(tmp, i);
            out += tmp;
        }
    }

    elgl->serialize_sendall(input_cip);
    for (int i = 1; i <= num_party; i++){
        if (party != i) {
            Ciphertext tmp_cip;
            elgl->deserialize_recv(tmp_cip, i);
            out_cip += tmp_cip;
        }
    }

    Fr out_ = thdcp(out_cip, elgl, global_pk, user_pks, io, pool, party, num_party, P_to_m, this);
    mcl::Vint o = out_.getMpz();
    o %= modulo;

    mcl::Vint o_ = out.get_message().getMpz();
    o_ %= modulo;
    
    if (o_ != o) {
        error("Reconstruct_interact error");
    }
    out.assign(o_);
    return out;
}

template <typename IO>
Plaintext LVT<IO>::Reconstruct_easy(Plaintext input, ELGL<IO>* elgl, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, mcl::Vint modulo){
    Plaintext out = input;
    elgl->serialize_sendall(input);

    for (int i = 1; i <= num_party; i++){
        if (party != i) {
            Plaintext tmp;
            elgl->deserialize_recv(tmp, i);
            out += tmp;
        }
    }
    mcl::Vint o_ = out.get_message().getMpz();
    o_ %= modulo;
    out.assign(o_);
    return out;
}

template <typename IO>
LVT<IO>::~LVT(){
}

template <typename IO>
std::vector<Fr> thdcp_batch(std::vector<Ciphertext>& c_batch, ELGL<IO>* elgl, const ELGL_PK& global_pk, const std::vector<ELGL_PK>& user_pks, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, std::map<std::string, Fr>& P_to_m, LVT<IO>* lvt
) {
    size_t batch_size = c_batch.size();
    if (batch_size == 0) return {};
    Plaintext sk(elgl->kp.get_sk().get_sk());
    std::vector<BLS12381Element> local_ask_batch(batch_size);
    std::vector<std::vector<BLS12381Element>> ask_parts_batch(batch_size, std::vector<BLS12381Element>(num_party));
    std::vector<std::future<void>> compute_futures;
    size_t num_threads = std::min(static_cast<size_t>(thread_num), batch_size);
    size_t block_size = (batch_size + num_threads - 1) / num_threads;
    for (size_t t = 0; t < num_threads; ++t) {
        size_t start = t * block_size;
        size_t end = std::min(start + block_size, batch_size);
        if (start < end) {
            compute_futures.push_back(pool->enqueue([&, start, end]() {
                for (size_t i = start; i < end; ++i) {
                    local_ask_batch[i] = c_batch[i].get_c0() * sk.get_message();
                    ask_parts_batch[i][party - 1] = local_ask_batch[i];
                }
            }));
        }
    }
    for (auto& fut : compute_futures) fut.get();
    compute_futures.clear();
    std::vector<std::string> commits(batch_size), responses(batch_size);
    for (size_t t = 0; t < num_threads; ++t) {
        size_t start = t * block_size;
        size_t end = std::min(start + block_size, batch_size);
        if (start < end) {
            compute_futures.push_back(pool->enqueue([&, start, end]() {
                ExpProof exp_proof(global_pk);
                ExpProver exp_prover(exp_proof);
                BLS12381Element y1 = user_pks[party-1].get_pk();
                for (size_t i = start; i < end; ++i) {
                    std::stringstream commit, response;
                    BLS12381Element g1 = c_batch[i].get_c0();
                    try {
                        exp_prover.NIZKPoK(exp_proof, commit, response, g1, y1, local_ask_batch[i], sk, party, pool);
                        commits[i] = commit.str();
                        responses[i] = response.str();
                    } catch (const std::exception& e) {
                        std::cerr << "Error generating proof for ciphertext " << i << ": " << e.what() << std::endl;
                        throw;
                    }
                }
            }));
        }
    }
    for (auto& fut : compute_futures) fut.get();
    compute_futures.clear();
    std::stringstream batch_commits, batch_responses;
    batch_commits << batch_size << "|";
    batch_responses << batch_size << "|";
    for (size_t i = 0; i < batch_size; ++i) {
        batch_commits << commits[i].length() << "|" << commits[i];
        batch_responses << responses[i].length() << "|" << responses[i];
    }
    std::stringstream commit_b64, response_b64;
    commit_b64 << base64_encode(batch_commits.str());
    response_b64 << base64_encode(batch_responses.str());
    elgl->serialize_sendall_(commit_b64);
    elgl->serialize_sendall_(response_b64);
    std::vector<std::future<void>> verify_futures;
    std::mutex ask_parts_mutex;
    for (int i = 1; i <= num_party; ++i) {
        if (i != party) {
            verify_futures.push_back(pool->enqueue([&, i]() {
                try {
                    std::stringstream local_commit_stream, local_response_stream;
                    elgl->deserialize_recv_(local_commit_stream, i);
                    elgl->deserialize_recv_(local_response_stream, i);
                    std::string comm_raw = base64_decode(local_commit_stream.str());
                    std::string resp_raw = base64_decode(local_response_stream.str());
                    std::stringstream comm_stream(comm_raw), resp_stream(resp_raw);
                    size_t received_batch_size;
                    char delimiter;
                    comm_stream >> received_batch_size >> delimiter;
                    resp_stream >> received_batch_size >> delimiter;
                    if (received_batch_size != batch_size) {
                        throw std::runtime_error("Batch size mismatch from party " + std::to_string(i));
                    }
                    std::vector<BLS12381Element> batch_ask_i(batch_size);
                    ExpProof local_exp_proof(global_pk);
                    ExpVerifier exp_verifier(local_exp_proof);
                    BLS12381Element y1_other = user_pks[i - 1].get_pk();
                    for (size_t j = 0; j < batch_size; ++j) {
                        size_t comm_len, resp_len;
                        comm_stream >> comm_len >> delimiter;
                        resp_stream >> resp_len >> delimiter;
                        std::string single_commit(comm_len, '\0'), single_response(resp_len, '\0');
                        comm_stream.read(&single_commit[0], comm_len);
                        resp_stream.read(&single_response[0], resp_len);
                        std::stringstream single_comm_stream(single_commit), single_resp_stream(single_response);
                        BLS12381Element g1 = c_batch[j].get_c0();
                        BLS12381Element ask_i;
                        exp_verifier.NIZKPoK(g1, y1_other, ask_i, single_comm_stream, single_resp_stream, pool, i);
                        batch_ask_i[j] = ask_i;
                    }
                    std::lock_guard<std::mutex> lock(ask_parts_mutex);
                    for (size_t j = 0; j < batch_size; ++j) {
                        ask_parts_batch[j][i - 1] = batch_ask_i[j];
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Error verifying proofs from party " << i << ": " << e.what() << std::endl;
                    throw;
                }
            }));
        }
    }
    for (auto& fut : verify_futures) fut.get();
    verify_futures.clear();
    std::vector<Fr> results(batch_size);
    for (size_t t = 0; t < num_threads; ++t) {
        size_t start = t * block_size;
        size_t end = std::min(start + block_size, batch_size);
        if (start < end) {
            compute_futures.push_back(pool->enqueue([&, start, end]() {
                for (size_t i = start; i < end; ++i) {
                    BLS12381Element pi_ask = c_batch[i].get_c1();
                    for (const auto& ask_i : ask_parts_batch[i]) {
                        pi_ask -= ask_i;
                    }
                    std::string key = pi_ask.getPoint().getStr();
                    Fr y = 0;
                    results[i] = y;
                }
            }));
        }
    }
    for (auto& fut : compute_futures) fut.get();
    return results;
}

template <typename IO>
vector<BLS12381Element> thdcp__batch(vector<Ciphertext>& c_batch, ELGL<IO>* elgl,const ELGL_PK& global_pk,const std::vector<ELGL_PK>& user_pks, MPIOChannel<IO>* io, ThreadPool* pool, int party, int num_party, std::map<std::string, Fr>& P_to_m
) {
    size_t batch_size = c_batch.size();
    if (batch_size == 0) return {};
    Plaintext sk(elgl->kp.get_sk().get_sk());
    vector<BLS12381Element> ask_batch(batch_size);
    vector<vector<BLS12381Element>> ask_parts_batch(batch_size, vector<BLS12381Element>(num_party));
    vector<BLS12381Element> pi_ask_batch(batch_size);
    vector<future<void>> futures;
    size_t num_threads = std::min(static_cast<size_t>(32), std::max(static_cast<size_t>(1), batch_size / 4096));
    size_t block_size = (batch_size + num_threads - 1) / num_threads;
    futures.reserve(num_threads);

    for (size_t t = 0; t < num_threads; t++) {
        size_t start = t * block_size;
        size_t end = std::min(batch_size, start + block_size);
        futures.push_back(pool->enqueue([start, end, &c_batch, &ask_batch, &ask_parts_batch, party, &sk]() {
            for (size_t i = start; i < end; i++) {
                ask_batch[i] = c_batch[i].get_c0() * sk.get_message();
                ask_parts_batch[i][party - 1] = ask_batch[i];
            }
        }));
    }
    for (auto& fut : futures) fut.get();
    futures.clear();
    std::stringstream ss;
    for (const auto& ask : ask_batch) {
        ask.pack(ss);
    }
    std::string serialized_data = ss.str();
    vector<future<void>> send_futures;
    for (int p = 1; p <= num_party; p++) {
        if (p != party) {
            send_futures.push_back(pool->enqueue([io, p, &serialized_data]() {
                io->send_data(p, serialized_data.data(), serialized_data.size());
            }));
        }
    }
    vector<future<void>> recv_futures;
    std::mutex parts_mutex;
    
    for (int p = 1; p <= num_party; p++) {
        if (p != party) {
            recv_futures.push_back(pool->enqueue([p, batch_size, io, &ask_parts_batch, &parts_mutex]() {
                int recv_size;
                void* recv_data = io->recv_data(p, recv_size);
                
                if (recv_data) {
                    try {
                        std::stringstream recv_ss;
                        recv_ss.write(static_cast<char*>(recv_data), recv_size);
                        
                        std::vector<BLS12381Element> received_asks(batch_size);
                        for (size_t i = 0; i < batch_size; i++) {
                            received_asks[i].unpack(recv_ss);
                        }
                        std::lock_guard<std::mutex> lock(parts_mutex);
                        for (size_t i = 0; i < batch_size; i++) {
                            ask_parts_batch[i][p-1] = received_asks[i];
                        }
                    } catch (const std::exception& e) {
                        std::cerr << "Error processing received data: " << e.what() << std::endl;
                    }
                    free(recv_data);
                }
            }));
        }
    }
    for (auto& fut : send_futures) fut.get();
    for (auto& fut : recv_futures) fut.get();
    for (size_t t = 0; t < num_threads; t++) {
        size_t start = t * block_size;
        size_t end = std::min(batch_size, start + block_size);
        futures.push_back(pool->enqueue([start, end, &c_batch, &ask_parts_batch, &pi_ask_batch]() {
            for (size_t i = start; i < end; i++) {
                pi_ask_batch[i] = c_batch[i].get_c1();
                for (const auto& ask_i : ask_parts_batch[i]) {
                    pi_ask_batch[i] -= ask_i;
                }
            }
        }));
    }
    for (auto& fut : futures) fut.get();

    return pi_ask_batch;
}

}

void serializeTable(vector<int64_t>& table, const char* filename, size_t se = 1<<16) {
    if (table.size() > se) {
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