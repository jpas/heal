#ifndef HEAL_EXAMPLES_STATS_H_
#define HEAL_EXAMPLES_STATS_H_

template <typename B, typename T>
auto average(const T& x, const T& mask)
  -> typename B::scalar_type
{
  // server side

  auto masked = x * mask;

  auto v_n = mask.inner_sum();
  auto v_sum = masked.inner_sum();

  // send v_* back to client

  auto n = v_n.extract_at(0);
  auto sum = v_sum.extract_at(0);

  return sum / n;
}


template <typename B, typename T>
auto variance(const T& x, const T& mask)
  -> typename B::scalar_type
{
  // Using the naive algorithm with the shortcut formula.
  // This algorithm is prone to catastrophic cancellation.

  // server side

  auto masked_x = x * mask;
  auto v_n = mask.inner_sum();
  auto v_sum_x = masked_x.inner_sum();
  auto v_sum_xx = (masked_x * masked_x).inner_sum();

  // send v_* back to client

  auto n = v_n.extract_at(0);
  auto sum_x = v_sum_x.extract_at(0);
  auto sum_xx = v_sum_xx.extract_at(0);

  return (sum_xx - sum_x*sum_x/n) / n;
}


template <typename B, typename T>
auto covariance(const T& x, const T& y, const T& mask)
  -> typename B::scalar_type
{
  // Using the naive algorithm with the shortcut formula and use the same mask
  // for x and y.
  // This algorithm is prone to catastrophic cancellation.

  // server side

  auto masked_x = x * mask;
  auto masked_y = y * mask;

  auto v_n = mask.inner_sum();
  auto v_sum_x = masked_x.inner_sum();
  auto v_sum_y = masked_y.inner_sum();
  auto v_sum_xy = (masked_x * masked_y).inner_sum();

  // send v_* back to client

  auto n = v_n.extract_at(0);
  auto sum_x = v_sum_x.extract_at(0);
  auto sum_y = v_sum_y.extract_at(0);
  auto sum_xy = v_sum_xy.extract_at(0);

  return (sum_xy - sum_x*sum_y/n) / n;
}


template <typename B, typename T>
auto pow(const T& x, uint64_t n)
  -> T
{
  if (n == 0) {
    return x.make_one();
  }

  T y = x;
  while (n > 0) {
    if (n%2 == 1) {
      y *= x;
    }

    n >>= 1;
    y *= y;
  }

  return y;
}

// Returns a vector of the powers \(x^k\) where \(0 <= k <= n\). Each power is
// computed using \(O(\log(k))\) multiplications.
template <typename B, typename T>
auto pow_up_to(const T& x, uint64_t n)
  -> vector<T>
{
  vector<T> powers(n+1);
  powers[0] = x.make_one();

  if (n >= 1) {
    powers[1] = x;
  }

  for (uint64_t i = 2; i <= n; i += 1) {
    if (i%2 == 0) {
      powers[i] = powers[i/2] * powers[i/2];
    } else {
      powers[i] = powers[i-1] * x;
    }
  }

  return powers;
}


// Computes the approximation \(e^x \approx \sum^{n}_{k=0} \frac{x^k}{k!}\).
// The final term is computed using \(O(\log(n))\) multiplications.
template <typename B, typename T>
auto exp_approx(const T& x, uint64_t n) -> T
{
  // This algorithm is unsuitible for CKKS schemes as each successive power
  // will be at a lower level to keep scaling for addition.
  vector<T> powers = powers_up_to(x, n);

  T y = x.make_one();
  uint64_t factorial = 1;
  for (uint64_t k = 1; k <= n; k += 1) {
    factorial *= k;
    y += powers[k] / factorial;
  }

  return y;
}


#endif // HEAL_EXAMPLES_STATS_H_
