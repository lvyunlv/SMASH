#include "libelgl/elgl/FFT.h"
#include "libelgl/elgl/Plaintext.h"
#include "libelgl/elgl/BLS12381Element.h"
#include <iostream>
#include <chrono>
using namespace std;
int main() {
    BLS12381Element::init();
    BLS12381Element G = BLS12381Element(1);

    mcl::Unit N = 65536;
    Plaintext alpha;

    mpz_class p = Fr::getOp().mp; 
    
    Plaintext g,exp;
    g.assign(5);
    cout << "g: " << g.get_message() << endl;

    exp.assign((p - 1)/N);
    cout << "exp = (p-1)/N: " << exp.get_message().getStr() << endl;

    Plaintext::pow(alpha, g, exp);
    cout << "alpha: " << alpha.get_message() << endl;

    Plaintext alpha_inv;
    Plaintext p_1;
    p_1.assign(p-1);
    Plaintext::pow(alpha_inv, g, p_1-exp);
    cout << "alpha_inv: " << alpha_inv.get_message() << endl;

    std::vector<BLS12381Element> input(N);
    for (size_t i = 0; i < N; ++i) {
        input[i] = G * i ; 
    }

    std::vector<BLS12381Element> output(N);
    std::vector<BLS12381Element> output_p(N);

    auto start = std::chrono::high_resolution_clock::now();
    FFT(input, output, alpha.get_message(), N);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = end - start;
    std::cout << "prove end. Time: " << duration.count() << " ms" << std::endl;

    start = std::chrono::high_resolution_clock::now();
    FFT_Para(input, output_p, alpha.get_message(), N);
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "prove end. Time: " << duration.count() << " ms" << std::endl;

    // check if output == output_p
    for (size_t i = 0; i < N; ++i) {
        if (output[i]!= output_p[i]){
            return 1;
        }
    }
    std::vector<BLS12381Element> inverse_output(N);

    return 0;
}