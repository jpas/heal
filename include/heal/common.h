#ifndef HEAL_COMMON_H_
#define HEAL_COMMON_H_

#include <cstddef>
#include <cinttypes>
#include <ostream>

namespace heal {

enum class security {
  hestd_classic_128,
  hestd_classic_192,
  hestd_classic_256,
  hestd_quantum_128,
  hestd_quantum_192,
  hestd_quantum_256,
};


struct BFVOptions {
  heal::security security = heal::security::hestd_classic_128;
  std::size_t degree;
  std::uint64_t plain_modulus = 0;
  std::uint64_t plain_modulus_bits = 0;
};


struct DoMaintainance {
  bool bootstrap = true;
  bool relinearize = true;
  bool rescale = true;
};


inline std::ostream& operator<<(std::ostream& os, const BFVOptions& opt)
{
  os << "BFVOptions{"
     << "degree=" << opt.degree
     << ","
     << "plain_modulus=" << opt.plain_modulus
     << ","
     << "plain_modulus_bits=" << opt.plain_modulus_bits
     << "}";
  return os;
}


struct CKKSOptions {
  heal::security security = heal::security::hestd_classic_128;
  size_t degree;
  size_t levels;
  double default_scale;
};


inline std::ostream& operator<<(std::ostream& os, const CKKSOptions& opt)
{
  os << "CKKSOptions{"
     << "degree=" << opt.degree
     << ","
     << "levels=" << opt.levels
     << ","
     << "default_scale=" << opt.default_scale
     << "}";
  return os;
}

} // namespace heal

#endif // HEAL_COMMON_H_
