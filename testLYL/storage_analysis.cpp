#include "emp-aby/lvt.h"
#include "emp-aby/io/multi-io.hpp"
#include <memory>
#include <sys/resource.h>
#include <unistd.h>
#include <fstream>
#include <iomanip>

using namespace emp;

// 存储分析结构体
struct StorageMetrics {
    size_t lut_share_size = 0;           // LUT shares大小
    size_t cip_lut_size = 0;             // 加密LUT大小
    size_t cr_i_size = 0;                // 旋转密文大小
    size_t user_pk_size = 0;             // 用户公钥大小
    size_t global_pk_size = 0;           // 全局公钥大小
    size_t rotation_size = 0;            // 旋转值大小
    size_t table_size = 0;               // 原始表大小
    size_t p_to_m_size = 0;              // P_to_m映射大小
    size_t bsgs_size = 0;                // BSGS预计算大小
    size_t total_memory = 0;             // 总内存使用
    size_t peak_memory = 0;              // 峰值内存使用
    
    void calculate_total() {
        total_memory = lut_share_size + cip_lut_size + cr_i_size + 
                      user_pk_size + global_pk_size + rotation_size + 
                      table_size + p_to_m_size + bsgs_size;
    }
    
    void print_metrics(int party_id, int num_parties, int table_size_bits, int m_bits) {
        std::cout << "\n=== Storage Analysis for Party " << party_id << " ===" << std::endl;
        std::cout << "Configuration: " << num_parties << " parties, table_size=2^" << table_size_bits 
                  << ", m_bits=" << m_bits << std::endl;
        std::cout << std::fixed << std::setprecision(2);
        std::cout << "LUT Shares:           " << std::setw(10) << lut_share_size / 1024.0 / 1024.0 << " MB" << std::endl;
        std::cout << "Encrypted LUT:        " << std::setw(10) << cip_lut_size / 1024.0 / 1024.0 << " MB" << std::endl;
        std::cout << "Rotation Ciphertexts: " << std::setw(10) << cr_i_size / 1024.0 / 1024.0 << " MB" << std::endl;
        std::cout << "User Public Keys:     " << std::setw(10) << user_pk_size / 1024.0 / 1024.0 << " MB" << std::endl;
        std::cout << "Global Public Key:    " << std::setw(10) << global_pk_size / 1024.0 / 1024.0 << " MB" << std::endl;
        std::cout << "Rotation Value:       " << std::setw(10) << rotation_size / 1024.0 / 1024.0 << " MB" << std::endl;
        std::cout << "Original Table:       " << std::setw(10) << table_size / 1024.0 / 1024.0 << " MB" << std::endl;
        std::cout << "P_to_m Mapping:       " << std::setw(10) << p_to_m_size / 1024.0 / 1024.0 << " MB" << std::endl;
        std::cout << "BSGS Precomputation:  " << std::setw(10) << bsgs_size / 1024.0 / 1024.0 << " MB" << std::endl;
        std::cout << "----------------------------------------" << std::endl;
        std::cout << "Total Storage:        " << std::setw(10) << total_memory / 1024.0 / 1024.0 << " MB" << std::endl;
        std::cout << "Peak Memory Usage:    " << std::setw(10) << peak_memory / 1024.0 / 1024.0 << " MB" << std::endl;
    }
    
    void save_to_file(const std::string& filename) {
        std::ofstream file(filename, std::ios::app);
        if (file.is_open()) {
            file << total_memory << "," << peak_memory << "," 
                 << lut_share_size << "," << cip_lut_size << "," 
                 << cr_i_size << "," << user_pk_size << "," 
                 << global_pk_size << "," << rotation_size << "," 
                 << table_size << "," << p_to_m_size << "," 
                 << bsgs_size << std::endl;
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
StorageMetrics analyze_lvt_storage(LVT<MultiIOBase>* lvt, int party_id, int num_parties, int table_size_bits, int m_bits) {
    StorageMetrics metrics;
    
    // 计算LUT shares大小
    size_t tb_size = 1ULL << table_size_bits;
    metrics.lut_share_size = lvt->lut_share.size() * sizeof(Plaintext);
    
    // 计算加密LUT大小
    metrics.cip_lut_size = 0;
    for (const auto& party_lut : lvt->cip_lut) {
        metrics.cip_lut_size += party_lut.size() * sizeof(BLS12381Element);
    }
    
    // 计算旋转密文大小
    metrics.cr_i_size = lvt->cr_i.size() * sizeof(Ciphertext);
    
    // 计算用户公钥大小
    metrics.user_pk_size = lvt->user_pk.size() * sizeof(ELGL_PK);
    
    // 计算全局公钥大小
    metrics.global_pk_size = sizeof(ELGL_PK);
    
    // 计算旋转值大小
    metrics.rotation_size = sizeof(Plaintext);
    
    // 计算原始表大小
    metrics.table_size = lvt->table.size() * sizeof(int64_t);
    
    // 计算P_to_m映射大小（估算）
    size_t m_size = 1ULL << m_bits;
    if (m_bits <= 14) {
        // 对于小m_bits，P_to_m包含所有可能的点
        size_t max_exponent = 2 * m_size * num_parties;
        if (max_exponent <= 1ULL << 8) {
            metrics.p_to_m_size = max_exponent * (sizeof(std::string) + sizeof(Fr));
        } else {
            metrics.p_to_m_size = (1ULL << 18) * (sizeof(std::string) + sizeof(Fr));
        }
    }
    
    // 计算BSGS预计算大小（估算）
    metrics.bsgs_size = 1ULL << 32 * sizeof(BLS12381Element); // 32位BSGS表
    
    // 计算总大小
    metrics.calculate_total();
    
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
    
    // 默认参数
    int table_size_bits = (argc > 4) ? std::stoi(argv[4]) : 10;
    int m_bits = (argc > 5) ? std::stoi(argv[5]) : 10;
    
    std::cout << "=== LVT Storage Analysis Tool ===" << std::endl;
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
    
    // 分析存储开销
    std::cout << "\nAnalyzing storage overhead..." << std::endl;
    StorageMetrics metrics = analyze_lvt_storage(lvt, party, num_party, table_size_bits, m_bits);
    
    // 打印分析结果
    metrics.print_metrics(party, num_party, table_size_bits, m_bits);
    
    // 保存结果到CSV文件
    std::string csv_filename = "storage_analysis_results.csv";
    if (party == 1) {
        // 创建CSV头部
        std::ofstream header_file(csv_filename);
        if (header_file.is_open()) {
            header_file << "total_memory,peak_memory,lut_share_size,cip_lut_size,cr_i_size,"
                       << "user_pk_size,global_pk_size,rotation_size,table_size,p_to_m_size,bsgs_size" << std::endl;
            header_file.close();
        }
    }
    metrics.save_to_file(csv_filename);
    
    // 执行密钥生成以观察内存变化
    std::cout << "\nExecuting DistKeyGen..." << std::endl;
    lvt->DistKeyGen();
    
    // 再次分析存储开销
    StorageMetrics metrics_after_keygen = analyze_lvt_storage(lvt, party, num_party, table_size_bits, m_bits);
    std::cout << "\n=== Storage Analysis After KeyGen ===" << std::endl;
    metrics_after_keygen.print_metrics(party, num_party, table_size_bits, m_bits);
    
    // 执行share生成
    std::cout << "\nExecuting generate_shares..." << std::endl;
    lvt->generate_shares(lvt->lut_share, lvt->rotation, lvt->table);
    
    // 最终存储分析
    StorageMetrics final_metrics = analyze_lvt_storage(lvt, party, num_party, table_size_bits, m_bits);
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
    
    std::cout << "\nStorage analysis completed for Party " << party << std::endl;
    return 0;
} 