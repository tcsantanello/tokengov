
#ifndef __TOKENIZATION_TOKEN_NO_VAULT_ERROR_HH__
#define __TOKENIZATION_TOKEN_NO_VAULT_ERROR_HH__

#include "exception.hh"

namespace token {
  namespace exceptions {
    class TokenNoVaultError : public TokenException {
     public:
      explicit TokenNoVaultError( std::string string )
        : TokenException( string ) {}
    };
  } // namespace exceptions
} // namespace token

#endif //__TOKENIZATION_TOKEN_NO_VAULT_ERROR_HH__
