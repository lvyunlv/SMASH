#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
#include <memory>
#include <sys/resource.h>
#include <unistd.h>

using namespace emp;

int party, port;
const static int threads = 8;
int num_party;
size_t get_current_memory_usage() {
    struct rusage r_usage;
    if (getrusage(RUSAGE_SELF, &r_usage) == 0) {
        return r_usage.ru_maxrss * 1024; 
    }
    return 0;
}
struct StorageMetrics {
    size_t offline_storage = 0;
    size_t online_storage = 0;
    size_t peak_memory = 0;
    
    void calculate_offline_storage(LVT<MultiIOBase>* lvt, int num_parties, int table_size_bits, int te) {
        size_t M = 1ULL << table_size_bits;
        size_t n = num_parties;            
        offline_storage += lvt->lut_share.size() * sizeof(Plaintext); 
        for (const auto& party_lut : lvt->cip_lut) {
            offline_storage += party_lut.size() * sizeof(BLS12381Element); 
        }
        offline_storage += lvt->cr_i.size() * sizeof(Ciphertext);
        offline_storage += lvt->user_pk.size() * sizeof(ELGL_PK);
        offline_storage += sizeof(ELGL_PK); 
        offline_storage += sizeof(Plaintext);
        offline_storage += lvt->table.size() * sizeof(int64_t);
        if (te <= 14) {
            size_t max_exponent = 2 * (1ULL << te) * num_parties;
            if (max_exponent <= 1ULL << 8) {
                offline_storage += max_exponent * (sizeof(std::string) + sizeof(Fr));
            } else {
                offline_storage += (1ULL << 18) * (sizeof(std::string) + sizeof(Fr));
            }
        }
        offline_storage += 1ULL << 32 * sizeof(BLS12381Element);
    }
    
    void calculate_online_storage(LVT<MultiIOBase>* lvt, int num_parties, int table_size_bits) {
        size_t n = num_parties; 
        online_storage += sizeof(Plaintext) * 10;  
        online_storage += sizeof(Ciphertext) * num_parties; 
        online_storage += sizeof(Plaintext) * 10; 
        online_storage += sizeof(Plaintext) * num_parties; 
        online_storage += sizeof(Ciphertext) * num_parties; 
    }
    
    void print_metrics() {
        std::cout << std::fixed << std::setprecision(6);
        std::cout << "Offline Storage:  " << std::setw(10) << offline_storage / 1024.0 / 1024.0 << " MB" << std::endl;
        std::cout << "Online Storage:   " << std::setw(10) << online_storage / 1024.0 / 1024.0 << " MB" << std::endl;
        std::cout << "Peak Memory:      " << std::setw(10) << peak_memory / 1024.0 / 1024.0 << " MB" << std::endl;
        std::cout << "Total Storage:    " << std::setw(10) << (offline_storage + online_storage) / 1024.0 / 1024.0 << " MB" << std::endl;
        
        // 理论分析
        std::cout << "\n=== Theoretical Analysis ===" << std::endl;
        std::cout << "Offline: O(M) field elements + O(Mn(|G1| + |G2|) + M log2 q) bits" << std::endl;
        std::cout << "Online:  O(n(|G1| + |G2|) + log2 q) bits per party" << std::endl;
    }
};
int main(int argc, char** argv) {
    BLS12381Element::init();
    if (argc < 5) {
        std::cout << "Format: <PartyID> <port> <num_parties> <network_condition>" << std::endl;
        return 0;
    }
    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);

    std::string network_condition = argv[4];
    initialize_network_conditions(network_condition);

    std::vector<std::pair<std::string, unsigned short>> net_config;
    if (argc >= 6) {
        const char* file = argv[5];
        FILE* f = fopen(file, "r");
        if (f != nullptr) {
            for (int i = 0; i < num_party; ++i) {
                char* c = (char*)malloc(15 * sizeof(char));
                uint p;
                fscanf(f, "%s %u", c, &p);
                net_config.push_back(std::make_pair(std::string(c), p));
                fflush(f);
            }
            fclose(f);
        } else {
            // fallback to localhost ports if file open fails
            for (int i = 0; i < num_party; ++i) {
                net_config.push_back({ "127.0.0.1", (unsigned short)(port + 4 * num_party * i) });
            }
        }
        std::cout << "Try open config file: " << file << std::endl;
        if (f == nullptr) {
            std::cout << "FAILED TO OPEN CONFIG FILE" << std::endl;
        }
    } else {
        for (int i = 0; i < num_party; ++i) {
            net_config.push_back({ "127.0.0.1", (unsigned short)(port + 4 * num_party * i) });
        }
    }

    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party, num_party, net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);
    int te = 10; int ad = 1 << te; int da = ad; 
    Fr alpha_fr = alpha_init(te);
    std::string tablefile = "init";
    emp::LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, tablefile, alpha_fr, te, te);
    cout << "Number of parties: " << num_party << endl;
    size_t initial_memory = get_current_memory_usage();
    // std::cout << "Initial memory usage: " << initial_memory / 1024.0 / 1024.0 << " MB" << std::endl;
    
    lvt->DistKeyGen();
    // cout << "Finish DistKeyGen" << endl;

    uint64_t bytes_start = io->get_total_bytes_sent();
    auto t1 = std::chrono::high_resolution_clock::now();

    lvt->generate_shares_(lvt->lut_share, lvt->rotation, lvt->table);
    mpz_class fd = ad;
    // cout << "Finish generate_shares" << endl;

    uint64_t bytes_end = io->get_total_bytes_sent();
    auto t2 = std::chrono::high_resolution_clock::now();
    double comm_kb = double(bytes_end - bytes_start) / 1024.0 / 1024.0;
    float time_ms = std::chrono::duration<float, std::milli>(t2 - t1).count() / 1000.0;
    cout << "Offline time: " << time_ms << " s, comm: " << comm_kb << " MB" << std::endl;

    //     // 计算Offline阶段存储开销
    // StorageMetrics storage_metrics;
    // storage_metrics.calculate_offline_storage(lvt, num_party, te, te);
    // storage_metrics.calculate_online_storage(lvt, num_party, te);
    // storage_metrics.peak_memory = get_current_memory_usage();
    
    // cout << "=== Storage Analysis ===" << std::endl;
    // storage_metrics.print_metrics();

    std::vector<Plaintext> x_share;
    // input_mode can be provided as the 7th argument if desired; default to txt
    std::string input_mode = (argc >= 7) ? argv[6] : "txt";
    std::string input_file = "../Input/Input-P." + input_mode;

    if (!fs::exists(input_file)) {
        std::cerr << "Error: input file does not exist: " << input_file << std::endl;
        return 1;
    }

    if (input_mode == "txt") {
        std::ifstream in_file(input_file);
        if (!in_file.is_open()) {
            std::cerr << "Error: cannot open txt input file: " << input_file << std::endl;
            return 1;
        }

        std::string line;
        while (std::getline(in_file, line)) {
            Plaintext x;
            x.assign(line);
            x_share.push_back(x);
        }
        in_file.close();
    }
    else if (input_mode == "bin") {
        std::ifstream in_file(input_file, std::ios::binary);
        if (!in_file.is_open()) {
            std::cerr << "Error: cannot open bin input file: " << input_file << std::endl;
            return 1;
        }

        uint64_t value;
        while (in_file.read(reinterpret_cast<char*>(&value), sizeof(uint64_t))) {
            Plaintext x;
            x.assign(value);
            x_share.push_back(x);
            if (value > (1ULL << te) - 1) {
                std::cerr << "Error: input value exceeds table size in Party: " << party << std::endl;
                std::cerr << "Error value: " << value << ", da = " << (1ULL << te) << std::endl;
                return 1;
            }
        }
        in_file.close();
    }
    else {
        std::cerr << "Error: invalid input mode '" << input_mode << "'. Use 'txt' or 'bin'." << std::endl;
        return 1;
    }

    int x_size = x_share.size();
    // cout << "Finish input generation (" << x_size << " elements from " << input_mode << " file)" << endl;

    Plaintext x_size_pt; x_size_pt.assign(x_size);
    elgl->serialize_sendall(x_size_pt);
    for (int i = 1; i <= num_party; i++) {
        if (i != party) {
            Plaintext x_size_pt_recv;
            elgl->deserialize_recv(x_size_pt_recv, i);
            if (int(x_size_pt_recv.get_message().getUint64()) != x_size) {
                std::cerr << "Error: input size does not match in Party: " << party << std::endl;
                return 1;
            }
        }
    }
    Plaintext tb_field = Plaintext(da);
    Plaintext value_field = Plaintext(ad);
    // cout << "Finish input size check" << endl;

    std::vector<Ciphertext> x_cipher(x_size);
    std::vector<vector<Ciphertext>> x_ciphers(num_party, vector<Ciphertext>(x_size));
    const int BATCH = 4096;
    for (int offset = 0; offset < x_size; offset += BATCH) {
        int cur = std::min(BATCH, x_size - offset);
        std::vector<std::future<void>> tasks;
        for (int i = 0; i < cur; ++i) {
            tasks.emplace_back(pool.enqueue([&, i, offset]() {
                x_cipher[offset + i] = lvt->global_pk.encrypt(x_share[offset + i]);
                x_ciphers[party-1][offset + i] = x_cipher[offset + i];
            }));
        }
        for (auto& t : tasks) t.get();
    }

    vector<std::future<void>> recv_futs;
    std::stringstream send_ss;
    for (size_t i = 0; i < x_size; ++i) {
        x_cipher[i].pack(send_ss);
    }
    for (size_t p = 1; p <= num_party; p++) {
        if (p == party) continue;
        recv_futs.push_back(pool.enqueue([&, p]() {
            std::stringstream recv_ss;
            elgl->deserialize_recv_(recv_ss, p);
            for (size_t i = 0; i < x_size; ++i) {
                x_ciphers[p-1][i].unpack(recv_ss);
            }
        }));
    }
    elgl->serialize_sendall_(send_ss);
    for (auto &f : recv_futs) f.get();
    recv_futs.clear();

    // std::vector<Plaintext> out(x_size);
    // std::vector<std::vector<Ciphertext>> out_ciphers(x_size, std::vector<Ciphertext>(num_party));

    uint64_t bytes_start1 = io->get_total_bytes_sent();
    auto t3 = std::chrono::high_resolution_clock::now();

    // //
    // std::vector<Ciphertext> cip_num(num_party);
    // for (int i = 0; i < num_party; ++i) {
    //     cip_num[i] = x_ciphers[i][0];
    // }
    // auto [out1, out2] = lvt->lookup_online(x_share[0], cip_num);

    auto [out1, out2] = lvt->lookup_online_batch(x_share, x_ciphers);

    uint64_t bytes_end1 = io->get_total_bytes_sent();
    auto t4 = std::chrono::high_resolution_clock::now();
    double comm_mb1 = double(bytes_end1 - bytes_start1) / 1024.0 / 1024.0;
    double time_ms1 = std::chrono::duration<double, std::milli>(t4 - t3).count() / 1000.0;
    cout << "Online time: " << time_ms1 << " s, comm: " << comm_mb1 << " MB" << std::endl;

    // 计算最终存储开销
    // size_t final_memory = get_current_memory_usage();
    // cout << "\n=== Final Storage Analysis ===" << std::endl;
    // cout << "Initial memory:  " << initial_memory / 1024.0 / 1024.0 << " MB" << std::endl;
    // cout << "Final memory:    " << final_memory / 1024.0 / 1024.0 << " MB" << std::endl;
    // cout << "Memory growth:   " << (final_memory - initial_memory) / 1024.0 / 1024.0 << " MB" << std::endl;

    // cout << "Finish online lookup" << endl;
    // lvt->Reconstruct_interact(out[0], out_ciphers[0][party-1], elgl, lvt->global_pk, lvt->user_pk, io, &pool, party, num_party, fd);
    // cout << "Finish Reconstruct_interact" << endl;
    // lvt->Reconstruct(out[0], out_ciphers[0], elgl, lvt->global_pk, lvt->user_pk, io, &pool, party, num_party, fd);
    // for (int i = 0; i < x_size; ++i) {
    //     Plaintext out_sum = out[i];
    //     elgl->serialize_sendall(out_sum);
    //     for (int i = 1; i <= num_party; i++) {
    //         if (i != party) {
    //             Plaintext out_recv;
    //             elgl->deserialize_recv(out_recv, i);
    //             out_sum += out_recv;
    //             out_sum = out_sum % value_field;
    //         }
    //     }
    //     elgl->serialize_sendall(out_sum);
    //     for (int i = 1; i <= num_party; i++) {
    //         if (i != party) {
    //             Plaintext table_pt_recv;
    //             elgl->deserialize_recv(table_pt_recv, i);
    //             if (table_pt_recv.get_message().getUint64() != table_x) {
    //                 std::cerr << "Error x_sum: " << party << std::endl;
    //                 return 1;
    //             }
    //             // cout << "party: " << party << " table_pt = " << table_pt_recv.get_message().getStr() << endl;
    //         }
    //     }
    // }

    // std::string output_file = "../../TestLYL/Output/Output-P" + std::to_string(party) + ".txt";
    // {
    //     std::ofstream out_file(output_file, std::ios::trunc);
    //     for (int i = 0; i < x_size; ++i) {
    //         out_file << out[i].get_message().getStr() << std::endl;
    //     }
    // }

    delete lvt;
    delete elgl;
    delete io;
    return 0;
}
