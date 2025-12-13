#include "Exp_prover.h"
#include <future>
ExpProver::ExpProver(ExpProof& proof) {
    k.resize(proof.n_proofs);
}

struct thread1Ret
{
    BLS12381Element v;
};

struct thread2Ret
{
    Plaintext s;
};

size_t ExpProver::NIZKPoK(ExpProof& P, std::stringstream&  ciphertexts, std::stringstream&  cleartexts,
    const BLS12381Element& g1,
    const vector<BLS12381Element>& y1,
    const vector<BLS12381Element>& y2,
    const vector<Plaintext>& x, ThreadPool* pool){

    Plaintext z;
    g1.pack(ciphertexts);
    for (unsigned int i = 0; i < y1.size(); i++){
        y1[i].pack(ciphertexts);
        y2[i].pack(ciphertexts);
    }
    z.setHashof(ciphertexts.str().c_str(), ciphertexts.str().size()); 
    std::vector<std::future<thread1Ret>> futures1;
    for (int i = 0; i < P.n_proofs; i++) {
        futures1.emplace_back(pool->enqueue([this, &g1, &z, i]() -> thread1Ret {
            BLS12381Element v;
            this->k[i].set_random();
            v = BLS12381Element(z.get_message()) + g1;
            v = v * k[i].get_message();
            return {v};
        }));
    }

    for (auto& f : futures1) {
        thread1Ret result = f.get();
        result.v.pack(ciphertexts);
    }

    P.set_challenge(ciphertexts);


    std::vector<std::future<thread2Ret>> futures2;
    // s = k - x * challenge
    for (int i = 0; i < P.n_proofs; i++){
        futures2.emplace_back(pool->enqueue([this, &x, &P, i]() -> thread2Ret {
            Plaintext s;
            s = this->k[i];
            s -= x[i] * P.challenge;
            return {s};
        }));
    }

    for (auto & f : futures2) {
        thread2Ret result = f.get();
        result.s.pack(cleartexts);
    }
    futures1.clear();
    futures2.clear();
    return report_size();
}

// Online 
size_t ExpProver::NIZKPoK(ExpProof& P, std::stringstream& ciphertexts, std::stringstream&  cleartexts,
    const BLS12381Element& g1,
    const BLS12381Element& y1,
    const BLS12381Element& y2,
    const Plaintext& x, int i, ThreadPool* pool){
    std::future<size_t> future = pool->enqueue([&, i]() -> size_t {
        std::stringstream hashbuf;
        BLS12381Element yy2 = y2;
        yy2.pack(hashbuf); 
        std::string hash_input = hashbuf.str();
        Plaintext z;
        z.setHashof(hash_input.c_str(), hash_input.size()); 
        this->k[0].set_random();
        yy2.pack(ciphertexts); 
        BLS12381Element v = BLS12381Element(z.get_message()) + g1;
        v = v * k[0].get_message();
        v.pack(ciphertexts);  

        P.set_challenge(ciphertexts);

        Plaintext s;
        s = this->k[0];
        s -= x * P.challenge;
        s.pack(cleartexts);

        return report_size();
    });
    return future.get();
}

size_t ExpProver::report_size(){
    size_t res = 0;
    res += sizeof(k);
    res *= k.size();
    return res;
}

// void ExpProver::report_size(MemoryUsage& res)
// {
//   res.update("prover k", k.size());
// }