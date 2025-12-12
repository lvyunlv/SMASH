#include "RotationVerifier.h"
#include <future>
RotationVerifier::RotationVerifier(RotationProof& proof): P(proof){
    miu_k.resize(proof.n_tilde);
    niu_k.resize(proof.n_tilde);
    rou_k.resize(proof.n_tilde);
}


void RotationVerifier::NIZKPoK(std::vector<BLS12381Element> &dx, std::vector<BLS12381Element> &ex, std::vector<BLS12381Element> &ax, std::vector<BLS12381Element> &bx, std::stringstream& ciphertexts, std::stringstream& cleartexts,
    const ELGL_PK& pk, const ELGL_PK& pk_tilde, ThreadPool * pool) {

        BLS12381Element g = BLS12381Element(1); ciphertexts.seekg(0); cleartexts.seekg(0);
        P.set_challenge(ciphertexts); ciphertexts.seekg(0); cleartexts.seekg(0);
        std::vector<BLS12381Element> ck(P.n_tilde + 1);
        std::vector<BLS12381Element> MK(P.n_tilde);
        ck[0] = g;
        for (size_t i = 0; i < P.n_tilde; i++) {
            ax[i].unpack(ciphertexts);
            bx[i].unpack(ciphertexts);
            dx[i].unpack(ciphertexts);
            ex[i].unpack(ciphertexts);
        }
        for (size_t i = 0; i < P.n_tilde; i++){
            ck[i+1].unpack(ciphertexts);
            MK[i].unpack(ciphertexts);
        }
        BLS12381Element C_Tilde, C;
        C_Tilde.unpack(ciphertexts);
        C.unpack(ciphertexts);
        sigma.unpack(cleartexts);
        eta.unpack(cleartexts);
        phi.unpack(cleartexts);
        for (size_t i = 0; i < P.n_tilde; i++){
            miu_k[i].unpack(cleartexts);
            niu_k[i].unpack(cleartexts);
            rou_k[i].unpack(cleartexts);
        }
        BLS12381Element h_tilde_eta;
        h_tilde_eta = pk_tilde.get_pk() * eta.get_message();
        BLS12381Element C_Tilde_c_n_gLambda;
        C_Tilde_c_n_gLambda = BLS12381Element(-1);
        C_Tilde_c_n_gLambda += ck[P.n_tilde];
        C_Tilde_c_n_gLambda *= P.challenge.get_message();
        C_Tilde_c_n_gLambda += C_Tilde;
        std::stringstream tmp_pack;
        std::vector<Plaintext> z(3);
        tmp_pack.str("");
        tmp_pack.clear();
        tmp_pack << 0;
        ax[0].pack(tmp_pack);
        bx[0].pack(tmp_pack);
        dx[0].pack(tmp_pack);
        ex[0].pack(tmp_pack);
        z[0].setHashof(tmp_pack.str().c_str(), tmp_pack.str().size());
        z[1].setHashof(tmp_pack.str().c_str(), tmp_pack.str().size());
        z[2].setHashof(tmp_pack.str().c_str(), tmp_pack.str().size());
        std::vector<Plaintext> yk(P.n_tilde);
        BLS12381Element L, R;int n_tilde=32;Plaintext tmp;
        std::vector<std::future<void> >futures;
        futures.reserve(P.n_tilde);
        for (size_t i = 0; i < P.n_tilde; i++){
            futures.push_back(pool->enqueue([&, i](){
                std::stringstream tmp_pack;
                tmp_pack.str("");
                tmp_pack.clear();
                ax[i].pack(tmp_pack);
                bx[i].pack(tmp_pack);
                dx[i].pack(tmp_pack);
                ex[i].pack(tmp_pack);
                tmp_pack << i;
                yk[i].setHashof(tmp_pack.str().c_str(), tmp_pack.str().size());
                }));
        }
        for (auto& future : futures) {
            future.get();
        }
        futures.clear();
        for (size_t i=0; i<n_tilde; i++) {
            futures.push_back(pool->enqueue([&, i]() {
                Plaintext tmp;
                BLS12381Element local_L, local_R;
                tmp = z[0]*miu_k[i] + z[1]*niu_k[i];
                local_L = BLS12381Element(tmp.get_message());
                tmp = z[0] * rou_k[i];
                tmp += z[2] * niu_k[i];
                local_L += pk.get_pk() * tmp.get_message();
                tmp = z[1] * miu_k[i];
                local_L += ax[i] * tmp.get_message();
                tmp = z[2] * miu_k[i];
                local_L += bx[i] * tmp.get_message();
                local_R = MK[i];
                tmp = P.challenge * z[0];
                local_R += ck[i] * tmp.get_message();
                tmp = P.challenge * z[1];
                local_R += dx[i] * tmp.get_message();
                tmp = P.challenge * z[2];
                local_R += ex[i] * tmp.get_message();
                if (local_L != local_R) {
                    #pragma omp critical
                    std::cout << "error" << std::endl;
                }
            }));
        }
        for (auto& future : futures) {
            future.get();
        }
    }
