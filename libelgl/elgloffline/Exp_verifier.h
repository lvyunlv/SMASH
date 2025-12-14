#ifndef EXP_VERIFIER_H
#define EXP_VERIFIER_H

#include "Exp_proof.h"
#include "emp-aby/utils.h"

class ExpVerifier{
    vector<Plaintext> s;
    ExpProof &P;
    public:
    ExpVerifier(ExpProof& proof);

    // void NIZKPoK(vector<BLS12381Element>& g1, vector<BLS12381Element>& y1,vector<BLS12381Element>& y2, std::stringstream&  ciphertexts, std::stringstream&  cleartexts);
    void NIZKPoK(BLS12381Element& g1, vector<BLS12381Element>& y1, vector<BLS12381Element>& y2, std::stringstream&  ciphertexts, std::stringstream&  cleartexts, ThreadPool* pool);
    void NIZKPoK_(BLS12381Element pk_tmp, vector<BLS12381Element>& a, vector<BLS12381Element>& ask, std::stringstream& recvss, ThreadPool* pool);
    void NIZKPoK(BLS12381Element& g1, BLS12381Element& y1, BLS12381Element& y2, std::stringstream&  ciphertexts, std::stringstream&  cleartexts, ThreadPool* pool, int i);

    size_t report_size(){return s.size() * sizeof(Plaintext);};
};
#endif