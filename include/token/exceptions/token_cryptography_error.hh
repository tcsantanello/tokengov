
#ifndef __TOKENIZATION_TOKEN_CRYPTOGRAPHY_ERROR_HH__
#define __TOKENIZATION_TOKEN_CRYPTOGRAPHY_ERROR_HH__

#include "exception.hh"

namespace token {
  namespace exceptions {
    class TokenCryptographyError : public TokenException {
     public:
      explicit TokenCryptographyError( std::string string )
        : TokenException( string ) {}
    };
  } // namespace exceptions
} // namespace token

#endif //__TOKENIZATION_TOKEN_CRYPTOGRAPHY_ERROR_HH__
