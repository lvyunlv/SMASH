#include "Schnorr_Prover.h"


Schnorr_Prover::Schnorr_Prover(Schnorr_Proof& proof) {
  rd.resize(proof.n_tilde);
}



size_t Schnorr_Prover::NIZKPoK(Schnorr_Proof& P, std::stringstream& ciphertexts, std::stringstream& cleartexts, const std::vector<BLS12381Element>& c, const std::vector<Plaintext>& x) {
    // Commit
    for (size_t i = 0; i < c.size(); i++)
        c[i].pack(ciphertexts);

    int V = P.n_tilde;

    BLS12381Element R;
    for (int i = 0; i < V; i++) {
        rd[i].set_random();

        R = BLS12381Element(rd[i].get_message());
        
        R.pack(ciphertexts);
    }

    P.set_challenge(ciphertexts);



    Plaintext z;

    for (size_t i = 0; i < P.n_tilde; i++) {
        z = P.challenge * x[i].get_message();
        z += rd[i].get_message();
        z.pack(cleartexts);
    }

  return report_size();
}

size_t Schnorr_Prover::report_size()
{
  size_t res = 0;
  res += sizeof(rd[0]) * rd.size();
  return res;
}

