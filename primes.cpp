#include "primes.h"
#include <math.h>
#include <random>
#include <algorithm>

vector<mpz_class> primes_cache = {1, 2, 3, 5, 7, 11, 13, 17, 19, 23};

template <typename Iter>
size_t index_of(Iter __start, Iter __element){
    return std::distance(__start, __element);
}

bool is_prime(mpz_class n) {
    /*if (binary_search(
        primes_cache.begin(), 
        primes_cache.end(), n))
        return true;*/
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    for (mpz_class i = 5; i * i <= n; i += 6)
        if (n % i == 0 || n % (i + 2) == 0) 
            return false;
    return true;
}
vector<mpz_class> get_primes(mpz_class n)
{
    mpz_class last = primes_cache.back();
    if (n >= last)
    {
        if (n > last)
        {    
            mpz_class num = last+2;
            while (num < n)
            {
                if(is_prime(num))
                    primes_cache.push_back(num);
                num += 2;
            }
        }
        return primes_cache;
    }
    
    vector<mpz_class> result; int i = 0;
    while (primes_cache[i] <= n)
        result.push_back(i++);
    return result;
}
mpz_class get_random_prime(mpz_class n, mpz_class m)
{
    get_primes(n);
    auto ub = index_of(primes_cache.begin(), find_if(primes_cache.rbegin(), primes_cache.rend(), [n](auto x){return x <= n; }).base()); 
    auto lb = index_of(primes_cache.begin(), find_if(primes_cache.begin(), primes_cache.end(), [m](auto x){return x >= m; }));
    std::random_device dev;
    std::mt19937 gen(dev());
    std::uniform_int_distribution<> distrib(lb, ub);
    int idx = distrib(gen);
    return primes_cache[idx];
}