#ifndef HEAL_EXAMPLES_STATS_H_
#define HEAL_EXAMPLES_STATS_H_

template <typename B, typename T>
auto
average(const T& x, const T& mask)
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
auto
variance(const T& x, const T& mask)
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
auto
covariance(const T& x, const T& y, const T& mask)
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

#endif // HEAL_EXAMPLES_STATS_H_
