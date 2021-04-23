#include <heal/heal.h>

#include <seal/seal.h>
#include <heal/backend/seal.h>

namespace heal::backend::seal {


::seal::sec_level_type convert(heal::security security) {
  switch (security) {
  case heal::security::hestd_classic_128:
    return ::seal::sec_level_type::tc128;
  case heal::security::hestd_classic_192:
    return ::seal::sec_level_type::tc192;
  case heal::security::hestd_classic_256:
    return ::seal::sec_level_type::tc256;
  default:
    return ::seal::sec_level_type::none;
  }
}


} // namespace heal::backend::seal
