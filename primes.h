#include <gmp.h>
#include <gmpxx.h>
#include <vector>
using namespace std;

#pragma once

bool is_prime(mpz_class);
vector<mpz_class> get_primes(mpz_class);
mpz_class get_random_prime(mpz_class, mpz_class=0);