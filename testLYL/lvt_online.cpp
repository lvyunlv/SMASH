#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
#include <memory>
#include <sys/resource.h>
#include <unistd.h>
using namespace emp;
int party, port;
const static int threads = 32;
int num_party;
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
    std::string tablefile = "init"; int aln = 24; Fr alpha_fr = alpha_init(aln);
    emp::LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, tablefile, alpha_fr, aln, aln);
    cout << "Number of parties: " << num_party << endl;
    lvt->DistKeyGen(0);
    uint64_t bytes_star1 = io->get_total_bytes_sent();
    auto t30 = std::chrono::high_resolution_clock::now();
    lvt->generate_shares_(lvt->lut_share, lvt->rotation, lvt->table);
    uint64_t bytes_en1 = io->get_total_bytes_sent();
    auto t40 = std::chrono::high_resolution_clock::now();
    double comm_m1 = double(bytes_en1 - bytes_star1) / 1024.0 / 1024.0;
    double time_m1 = std::chrono::duration<double, std::milli>(t40 - t30).count() / 1000.0;
    cout << "Online time: " << time_m1 << " s, comm: " << comm_m1 << " MB" << std::endl;
    std::vector<Plaintext> x_share;
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
            if (value > (1ULL << aln) - 1) {
                std::cerr << "Error: input value exceeds table size in Party: " << party << std::endl;
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
    uint64_t bytes_start1 = io->get_total_bytes_sent();
    auto t3 = std::chrono::high_resolution_clock::now();
    auto [out1, out2] = lvt->lookup_online_batch(x_share, x_ciphers);
    uint64_t bytes_end1 = io->get_total_bytes_sent();
    auto t4 = std::chrono::high_resolution_clock::now();
    double comm_mb1 = double(bytes_end1 - bytes_start1) / 1024.0 / 1024.0;
    double time_ms1 = std::chrono::duration<double, std::milli>(t4 - t3).count() / 1000.0;
    cout << "Online time: " << time_ms1 << " s, comm: " << comm_mb1 << " MB" << std::endl;
    delete lvt;
    delete elgl;
    delete io;
    return 0;
}
