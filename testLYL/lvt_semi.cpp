#include "emp-aby/lvt_semi_honest.h"
#include "emp-aby/io/multi-io.hpp"
#include <memory>
#include <sys/resource.h>
#include <unistd.h>
#include <filesystem>

using namespace emp;

size_t get_current_memory_usage() {
    struct rusage r_usage;
    if (getrusage(RUSAGE_SELF, &r_usage) == 0) {
        return r_usage.ru_maxrss * 1024; 
    }
    return 0;
}

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
    std::string tablefile = "init"; int aln = 8; int su = 1ULL << aln; Fr alpha_fr = alpha_init(aln);
    emp::LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, tablefile, alpha_fr, aln, aln);
    size_t initial_memory = get_current_memory_usage();
    lvt->DistKeyGen(1);lvt->generate_shares_(lvt->lut_share, lvt->rotation, lvt->table);
    std::vector<Plaintext> x_share;
    std::string input_file = "../../Input/Input-P.txt";
    {
        if (!fs::exists(input_file)) {
            std::cerr << "Error: input file does not exist: " << input_file << std::endl;
            return 1;
        }
        std::ifstream in_file(input_file);
        std::string line;
        while (std::getline(in_file, line)) {
            Plaintext x;
            x.assign(line);
            x_share.push_back(x);
            if (x.get_message().getUint64() > (1ULL << aln) - 1) {
                std::cerr << "Error: input value exceeds table size in Party: " << party << std::endl;
                cout << "Error value: " << x.get_message().getUint64() << ", su = " << (1ULL << aln) << endl;
                return 1;
            }
        }
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
    Plaintext tb_field = Plaintext(su);
    vector<Plaintext> x_sums(x_size);
    std::vector<std::future<void>> futs;
    futs.reserve(x_size);
    for (int i = 0; i < x_size; ++i) {
        futs.emplace_back(pool.enqueue([i, &x_sums, &x_share]() {
            x_sums[i] = x_share[i];
        }));
    }
    for (auto &f : futs) f.get();
    std::stringstream send_xss;
    for (int i = 0; i < x_size; ++i) {
        x_sums[i].pack(send_xss);
    }
    elgl->serialize_sendall_(send_xss);
    for (int p = 1; p <= num_party; ++p) {
        if (p == party) continue;
        std::stringstream recv_ss;
        elgl->deserialize_recv_(recv_ss, p);
        std::vector<Plaintext> tmp_recv(x_size);
        for (int i = 0; i < x_size; ++i) {
            tmp_recv[i].unpack(recv_ss);
        }
        {
            std::vector<std::future<void>> futs;
            futs.reserve(x_size);

            for (int i = 0; i < x_size; ++i) {
                futs.emplace_back(pool.enqueue([i, &x_sums, &tmp_recv, &tb_field]() {
                    x_sums[i] += tmp_recv[i];
                    x_sums[i] = x_sums[i] % tb_field;
                }));
            }
            for (auto &f : futs) f.get();
        }

    }
    vector<Plaintext> table_pts(x_size);
    {
        std::vector<std::future<void>> futs;
        futs.reserve(x_size);

        for (int i = 0; i < x_size; ++i) {
            futs.emplace_back(pool.enqueue([i, &table_pts, &x_sums, &lvt]() {
                uint64_t idx = x_sums[i].get_message().getUint64();
                uint64_t table_x = lvt->table[idx];
                table_pts[i] = Plaintext(table_x);
            }));
        }
        for (auto &f : futs) f.get();
    }
    std::stringstream send_tabless;
    for (int i = 0; i < x_size; ++i) {
        table_pts[i].pack(send_tabless);
    }
    elgl->serialize_sendall_(send_tabless);

    for (int p = 1; p <= num_party; ++p) {
        if (p == party) continue;
        std::stringstream recv_ss;
        elgl->deserialize_recv_(recv_ss, p);
        for (int i = 0; i < x_size; ++i) {
            Plaintext tpx;
            tpx.unpack(recv_ss);
            if (tpx.get_message().getUint64() != table_pts[i].get_message().getUint64()) {
                std::cerr << "Error: mismatched table_pt at index " << i << " from party " << p << std::endl;
                return 1;
            }
        }
    }
    std::vector<Plaintext> out(x_size);
    int bytes_start1 = io->get_total_bytes_sent();
    auto t3 = std::chrono::high_resolution_clock::now();
    auto output1 = lvt->lookup_online_batch(x_share);
    int bytes_end1 = io->get_total_bytes_sent();
    auto t4 = std::chrono::high_resolution_clock::now();
    float comm_kb1 = float(bytes_end1 - bytes_start1) / 1024.0 / 1024.0;
    float time_ms1 = std::chrono::duration<float, std::milli>(t4 - t3).count() / 1000.0;
    cout << "Online time: " << time_ms1 << " s, comm: " << comm_kb1 << " MB" << std::endl;

    delete lvt;
    delete elgl;
    delete io;
    return 0;
}
