#include "Commit_verifier.h"

CommitVerifier::CommitVerifier(CommProof& proof) :
    P(proof)
{
    sx.resize(proof.n_proofs);
    sr.resize(proof.n_proofs);
}

void CommitVerifier::NIZKPoK(vector<Ciphertext>& c,vector<BLS12381Element>& y3, std::stringstream& ciphertexts, std::stringstream& cleartexts, vector<BLS12381Element>& g1, const ELGL_PK& pk){
    P.set_challenge(ciphertexts);

    for (int i = 0; i < P.n_proofs; i++){
        g1[i].unpack(ciphertexts);
        c[i].unpack(ciphertexts);
        y3[i].unpack(ciphertexts);
    }

    BLS12381Element t1, t2, t3;
    
    Plaintext sx_tmp;
    Plaintext sr_tmp;

    BLS12381Element gsr, hsr, gsxhsr;

    BLS12381Element y_1_tmp, y_2_tmp;
    BLS12381Element t1y1lamda, t2y2lamda;
    BLS12381Element g1sxhsr;      

    BLS12381Element t3y3lambda;
    for (int i = 0; i < P.n_proofs; i++){
        sx_tmp.unpack(cleartexts);
        sr_tmp.unpack(cleartexts);

        t1.unpack(ciphertexts);
        t2.unpack(ciphertexts);
        t3.unpack(ciphertexts);
        
        gsr = BLS12381Element(sr_tmp.get_message());
        hsr = pk.get_pk() * sr_tmp.get_message();
        
        gsxhsr = BLS12381Element(sx_tmp.get_message());
        gsxhsr += hsr;
 
        t1y1lamda = c[i].get_c0() * P.challenge.get_message();
        t1y1lamda += t1;

        t2y2lamda = c[i].get_c1() * P.challenge.get_message();
        t2y2lamda += t2;

        
        g1sxhsr = g1[i] * sx_tmp.get_message();
        g1sxhsr += hsr;


        t3y3lambda = y3[i] * P.challenge.get_message();
        t3y3lambda += t3;

        if (gsr != t1y1lamda || gsxhsr != t2y2lamda || g1sxhsr != t3y3lambda ){
            throw runtime_error("invalid proof");
        }
    }
    cout << "valid proof" << endl;
}