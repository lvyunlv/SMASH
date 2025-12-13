#pragma once
#include "emp-aby/io/multi-io.hpp"
#include "emp-aby/io/mp_io_channel.h"
#include "emp-aby/lvt.h"
#include "emp-aby/elgl_interface.hpp"
#include "emp-aby/tiny.hpp"
#include "emp-aby/spdz2k.hpp"
#include "B2A_spdz2k.hpp"
#include <vector>
#include <mcl/vint.hpp>
#include <map>
#include <chrono>

namespace A2B_spdz2k {
using namespace emp;
using std::vector;
inline vector<TinyMAC<MultiIOBase>::LabeledShare> A2B(
    ELGL<MultiIOBase>* elgl,
    LVT<MultiIOBase>* lvt,
    TinyMAC<MultiIOBase>& tiny,
    SPDZ2k<MultiIOBase>& spdz2k,
    int party,
    int num_party,
    string nw, 
    MultiIO* io,
    ThreadPool* pool,
    const uint64_t& FIELD_SIZE,
    int l,
    const SPDZ2k<MultiIOBase>::LabeledShare& x_arith,
    std::chrono::_V2::system_clock::time_point& offline_time,
    int& offline_comm
) {
    int bytes = io->get_total_bytes_sent();
    auto t = std::chrono::high_resolution_clock::now();
    vector<TinyMAC<MultiIOBase>::LabeledShare> x_bool(l);
    vector<TinyMAC<MultiIOBase>::LabeledShare> r_bits(l);
    std::random_device rd;nta();std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bit_dis(0, 1);
    for (int i = 1; i < l; ++i) r_bits[i] = tiny.distributed_share(bit_dis(gen));
    SPDZ2k<MultiIOBase>::LabeledShare r_arith;
    r_arith = B2A_spdz2k::B2A_for_A2B(elgl, lvt, tiny, spdz2k, party, num_party, nw, io, pool, FIELD_SIZE, r_bits);
    auto tt = std::chrono::high_resolution_clock::now();
    int bytes_ = io->get_total_bytes_sent();
    double comm_kb1 = double(bytes_ - bytes) / 1024.0;
    double time_ms1 = std::chrono::duration<double, std::milli>(tt - t).count();
    std::cout << std::fixed << std::setprecision(6)
              << "Offline Communication: " << comm_kb1 << " KB, "
              << "Offline Time: " << time_ms1 << " ms" << std::endl;
    int bytes_start = io->get_total_bytes_sent();
    auto t1 = std::chrono::high_resolution_clock::now();
    SPDZ2k<MultiIOBase>::LabeledShare x_plus_r;
    x_plus_r = spdz2k.add(x_arith, r_arith);
    uint64_t u; nt(nw);
    u = spdz2k.reconstruct(x_plus_r);
    u = (u + FIELD_SIZE) % FIELD_SIZE;
    vector<uint8_t> u_bits(l, 0);
    uint64_t tmp = u;
    for (int i = 0; i < l; ++i) {
        u_bits[i] = (tmp & 1);
        tmp >>= 1;
    }
    vector<TinyMAC<MultiIOBase>::LabeledShare> u_bool(l);
    u_bool[0] = tiny.distributed_share(u_bits[0]);nta();
    x_bool[0] = tiny.add(u_bool[0], r_bits[0]);
    u_bool[1] = tiny.distributed_share(u_bits[1]);nta();
    x_bool[1] = tiny.add(u_bool[1], r_bits[1]);
    auto t2 = std::chrono::high_resolution_clock::now();
    for (int i = 2; i < l; ++i) u_bool[i] = tiny.distributed_share(u_bits[i]);
    for (int i = 2; i < l; ++i) x_bool[i] = tiny.add(u_bool[i], r_bits[i]);
    int bytes_end = io->get_total_bytes_sent();
    double comm_kb = double(bytes_end - bytes_start) / 1024.0;
    double time_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
    std::cout << std::fixed << std::setprecision(6)
    << "Online Communication: " << comm_kb << " KB, "
    << "Online Time: " << time_ms << " ms" << std::endl;
    return x_bool;
}
} // namespace A2B_spdz2k 