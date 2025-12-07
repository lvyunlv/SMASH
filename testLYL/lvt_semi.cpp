#include "emp-aby/lvt_semi_honest.h"
#include "emp-aby/io/multi-io.hpp"
#include <memory>
#include <sys/resource.h>
#include <unistd.h>

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
    if (argc < 4) {
        std::cout << "Format: <PartyID> <port> <num_parties> [tablefile|network]" << std::endl;
        std::cout << "Network options: local, lan, wan" << std::endl;
        return 0;
    }
    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);

    std::vector<std::pair<std::string, unsigned short>> net_config;
    // 支持传入网络条件："local", "lan", "wan"，或传入一个 net config 文件路径
    if (argc == 5) {
        const std::string arg4 = argv[4];
        if (arg4 == "local" || arg4 == "lan" || arg4 == "wan") {
            // 初始化网络模拟条件
            initialize_network_conditions(arg4);
            for (int i = 0; i < num_party; ++i) {
                net_config.push_back({ "127.0.0.1", static_cast<unsigned short>(port + 4 * num_party * i) });
            }
        } else {
            const char* file = argv[4];
            FILE* f = fopen(file, "r");
            if (!f) {
                std::cerr << "Error: cannot open net config file: " << file << std::endl;
                return 1;
            }
            for (int i = 0; i < num_party; ++i) {
                char* c = (char*)malloc(256 * sizeof(char));
                unsigned int p;
                if (fscanf(f, "%s %u", c, &p) != 2) {
                    std::cerr << "Error: bad net config format in file: " << file << std::endl;
                    free(c);
                    fclose(f);
                    return 1;
                }
                net_config.push_back(std::make_pair(std::string(c), static_cast<unsigned short>(p)));
                free(c);
            }
            fclose(f);
        }
    } else {
        for (int i = 0; i < num_party; ++i) {
            net_config.push_back({ "127.0.0.1", static_cast<unsigned short>(port + 4 * num_party * i) });
        }
    }

    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party, num_party, net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);
    int m_bits = 8; int m_size = 1 << m_bits; 
    int num = 8; int tb_size = 1ULL << num; 
    Fr alpha_fr = alpha_init(num);
    std::string tablefile = "init";
    emp::LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, tablefile, alpha_fr, num, m_bits);
    cout << "Table size: " << tb_size << endl;
    cout << "Number of parties: " << num_party << endl;
    // 记录初始内存使用
    size_t initial_memory = get_current_memory_usage();
    std::cout << "Initial memory usage: " << initial_memory / 1024.0 / 1024.0 << " MB" << std::endl;
    
    lvt->DistKeyGen();
    cout << "Finish DistKeyGen" << endl;

    int bytes_start = io->get_total_bytes_sent();
    auto t1 = std::chrono::high_resolution_clock::now();

    lvt->generate_shares(lvt->lut_share, lvt->rotation, lvt->table);
    mpz_class fd = m_size;
    cout << "Finish generate_shares" << endl;

    int bytes_end = io->get_total_bytes_sent();
    auto t2 = std::chrono::high_resolution_clock::now();
    float comm_kb = float(bytes_end - bytes_start) / 1024.0 / 1024.0;
    float time_ms = std::chrono::duration<float, std::milli>(t2 - t1).count() / 1000.0;
    cout << "Offline time: " << time_ms << " s, comm: " << comm_kb << " MB" << std::endl;

    std::vector<Plaintext> x_share;
    // std::string input_file = "../Input/Input-P" + std::to_string(party) + ".txt";
    std::string input_file = "../Input/Input-P.txt";
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
            if (x.get_message().getUint64() > (1ULL << num) - 1) {
                std::cerr << "Error: input value exceeds table size in Party: " << party << std::endl;
                cout << "Error value: " << x.get_message().getUint64() << ", tb_size = " << (1ULL << m_bits) << endl;
                return 1;
            }
        }
    }
    int x_size = x_share.size();
    cout << "Finish input generation" << endl;
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
    Plaintext tb_field = Plaintext(tb_size);
    Plaintext value_field = Plaintext(m_size);
    // cout << "Finish input size check" << endl;

    // Batch broadcast all x_share values to reduce round trips
    vector<Plaintext> x_sums(x_size);
    for (int i = 0; i < x_size; ++i) x_sums[i] = x_share[i];

    // pack all x_sums into a stream and broadcast to all other parties
    std::stringstream send_xss;
    for (int i = 0; i < x_size; ++i) {
        x_sums[i].pack(send_xss);
    }
    std::cout << "[P" << party << "] broadcasting " << x_size << " x_sums" << std::endl;
    elgl->serialize_sendall_(send_xss);

    // receive packed batches from all other parties and accumulate
    for (int p = 1; p <= num_party; ++p) {
        if (p == party) continue;
        std::stringstream recv_ss;
        elgl->deserialize_recv_(recv_ss, p);
        for (int i = 0; i < x_size; ++i) {
            Plaintext px;
            px.unpack(recv_ss);
            x_sums[i] += px;
            x_sums[i] = x_sums[i] % tb_field;
        }
        std::cout << "[P" << party << "] received x_sums from party " << p << std::endl;
    }

    // compute table points for all indices and broadcast them once
    std::stringstream send_tabless;
    vector<Plaintext> table_pts(x_size);
    for (int i = 0; i < x_size; ++i) {
        uint64_t table_x = lvt->table[x_sums[i].get_message().getUint64()];
        table_pts[i] = Plaintext(table_x);
        table_pts[i].pack(send_tabless);
    }
    std::cout << "[P" << party << "] broadcasting " << x_size << " table_pts" << std::endl;
    elgl->serialize_sendall_(send_tabless);

    // receive table batches from others and verify
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
        std::cout << "[P" << party << "] received table_pts from party " << p << std::endl;
    }
 cout << "here" << endl;
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
