#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
#include <memory>
#include <sys/resource.h>
#include <unistd.h>
#include <fstream>
#include <iomanip>

using namespace emp;

// 简化的存储分析结构体
struct SimpleStorageMetrics {
    size_t offline_storage = 0;    // Offline阶段存储开销
    size_t online_storage = 0;     // Online阶段存储开销
    size_t peak_memory = 0;        // 峰值内存使用
    
    void print_metrics(int party_id, int num_parties, int table_size_bits, int m_bits) {
        std::cout << "\n=== Storage Analysis for Party " << party_id << " ===" << std::endl;
        std::cout << "Configuration: " << num_parties << " parties, table_size=2^" << table_size_bits 
                  << ", m_bits=" << m_bits << std::endl;
        std::cout << std::fixed << std::setprecision(2);
        std::cout << "Offline Storage:  " << std::setw(10) << offline_storage / 1024.0 / 1024.0 << " MB" << std::endl;
        std::cout << "Online Storage:   " << std::setw(10) << online_storage / 1024.0 / 1024.0 << " MB" << std::endl;
        std::cout << "Peak Memory:      " << std::setw(10) << peak_memory / 1024.0 / 1024.0 << " MB" << std::endl;
        std::cout << "Total Storage:    " << std::setw(10) << (offline_storage + online_storage) / 1024.0 / 1024.0 << " MB" << std::endl;
    }
    
    void save_to_file(const std::string& filename) {
        std::ofstream file(filename, std::ios::app);
        if (file.is_open()) {
            file << offline_storage << "," << online_storage << "," << peak_memory << std::endl;
            file.close();
        }
    }
};

// 获取当前进程内存使用量
size_t get_current_memory_usage() {
    struct rusage r_usage;
    if (getrusage(RUSAGE_SELF, &r_usage) == 0) {
        return r_usage.ru_maxrss * 1024; // 转换为字节
    }
    return 0;
}

// 分析LVT对象的存储开销
SimpleStorageMetrics analyze_lvt_storage(LVT<MultiIOBase>* lvt, int party_id, int num_parties, int table_size_bits, int m_bits) {
    SimpleStorageMetrics metrics;
    
    // Offline阶段存储开销
    // 包括：LUT shares, 加密LUT, 旋转密文, 公钥, 原始表, P_to_m映射, BSGS预计算
    size_t tb_size = 1ULL << table_size_bits;
    size_t m_size = 1ULL << m_bits;
    
    // LUT shares
    metrics.offline_storage += lvt->lut_share.size() * sizeof(Plaintext);
    
    // 加密LUT
    for (const auto& party_lut : lvt->cip_lut) {
        metrics.offline_storage += party_lut.size() * sizeof(BLS12381Element);
    }
    
    // 旋转密文
    metrics.offline_storage += lvt->cr_i.size() * sizeof(Ciphertext);
    
    // 公钥
    metrics.offline_storage += lvt->user_pk.size() * sizeof(ELGL_PK);
    metrics.offline_storage += sizeof(ELGL_PK); // 全局公钥
    
    // 旋转值
    metrics.offline_storage += sizeof(Plaintext);
    
    // 原始表
    metrics.offline_storage += lvt->table.size() * sizeof(int64_t);
    
    // P_to_m映射（估算）
    if (m_bits <= 14) {
        size_t max_exponent = 2 * m_size * num_parties;
        if (max_exponent <= 1ULL << 8) {
            metrics.offline_storage += max_exponent * (sizeof(std::string) + sizeof(Fr));
        } else {
            metrics.offline_storage += (1ULL << 18) * (sizeof(std::string) + sizeof(Fr));
        }
    }
    
    // BSGS预计算（估算）
    metrics.offline_storage += 1ULL << 32 * sizeof(BLS12381Element);
    
    // Online阶段存储开销（估算）
    // 包括：输入数据、中间计算结果、输出数据
    metrics.online_storage = tb_size * sizeof(Plaintext) * 2; // 输入和输出
    
    // 获取峰值内存使用
    metrics.peak_memory = get_current_memory_usage();
    
    return metrics;
}

int party, port;
const static int threads = 32;
int num_party;

int main(int argc, char** argv) {
    BLS12381Element::init();
    if (argc < 4) {
        std::cout << "Format: <PartyID> <port> <num_parties> [table_size_bits] [m_bits]" << std::endl;
        return 0;
    }
    
    parse_party_and_port(argv, &party, &port);
    num_party = std::stoi(argv[3]);
    
    // 默认参数 - 匹配lvt.cpp中的设置
    int table_size_bits = (argc > 4) ? std::stoi(argv[4]) : 24;  // 改为24
    int m_bits = (argc > 5) ? std::stoi(argv[5]) : 24;           // 改为24
    
    std::cout << "=== Simple LVT Storage Analysis ===" << std::endl;
    std::cout << "Party: " << party << ", Total Parties: " << num_party << std::endl;
    std::cout << "Table Size: 2^" << table_size_bits << ", M Bits: " << m_bits << std::endl;
    
    // 网络配置
    std::vector<std::pair<std::string, unsigned short>> net_config;
    for (int i = 0; i < num_party; ++i) {
        net_config.push_back({ "127.0.0.1", port + 4 * num_party * i });
    }

    ThreadPool pool(threads);
    MultiIO* io = new MultiIO(party, num_party, net_config);
    ELGL<MultiIOBase>* elgl = new ELGL<MultiIOBase>(num_party, io, &pool, party);
    
    // 记录初始内存使用
    size_t initial_memory = get_current_memory_usage();
    std::cout << "Initial memory usage: " << initial_memory / 1024.0 / 1024.0 << " MB" << std::endl;
    
    // 创建LVT对象
    std::cout << "\nCreating LVT object..." << std::endl;
    Fr alpha_fr = alpha_init(table_size_bits);
    std::string tablefile = "init";
    emp::LVT<MultiIOBase>* lvt = new LVT<MultiIOBase>(num_party, party, io, &pool, elgl, tablefile, alpha_fr, table_size_bits, m_bits);
    
    // 分析Offline阶段存储开销
    std::cout << "\nAnalyzing Offline storage..." << std::endl;
    SimpleStorageMetrics offline_metrics = analyze_lvt_storage(lvt, party, num_party, table_size_bits, m_bits);
    offline_metrics.print_metrics(party, num_party, table_size_bits, m_bits);
    
    // 保存结果到CSV文件
    std::string csv_filename = "simple_storage_results.csv";
    if (party == 1) {
        // 创建CSV头部
        std::ofstream header_file(csv_filename);
        if (header_file.is_open()) {
            header_file << "offline_storage,online_storage,peak_memory" << std::endl;
            header_file.close();
        }
    }
    offline_metrics.save_to_file(csv_filename);
    
    // 执行密钥生成
    std::cout << "\nExecuting DistKeyGen..." << std::endl;
    lvt->DistKeyGen();
    
    // 执行share生成
    std::cout << "\nExecuting generate_shares..." << std::endl;
    lvt->generate_shares(lvt->lut_share, lvt->rotation, lvt->table);
    
    // 最终存储分析
    SimpleStorageMetrics final_metrics = analyze_lvt_storage(lvt, party, num_party, table_size_bits, m_bits);
    std::cout << "\n=== Final Storage Analysis ===" << std::endl;
    final_metrics.print_metrics(party, num_party, table_size_bits, m_bits);
    
    // 计算内存增长
    size_t final_memory = get_current_memory_usage();
    std::cout << "\n=== Memory Growth Analysis ===" << std::endl;
    std::cout << "Initial memory:  " << initial_memory / 1024.0 / 1024.0 << " MB" << std::endl;
    std::cout << "Final memory:    " << final_memory / 1024.0 / 1024.0 << " MB" << std::endl;
    std::cout << "Memory growth:   " << (final_memory - initial_memory) / 1024.0 / 1024.0 << " MB" << std::endl;
    
    // 清理资源
    delete lvt;
    delete elgl;
    delete io;
    
    std::cout << "\nSimple storage analysis completed for Party " << party << std::endl;
    return 0;
} 