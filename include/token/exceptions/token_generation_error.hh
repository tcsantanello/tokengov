
#ifndef __TOKENIZATION_TOKEN_GENERATION_ERROR_HH__
#define __TOKENIZATION_TOKEN_GENERATION_ERROR_HH__

#include "exception.hh"

namespace token {
  namespace exceptions {
    class TokenGenerationError : public TokenException {
     public:
      explicit TokenGenerationError( std::string string )
        : TokenException( string ) {}
    };
  } // namespace exceptions
} // namespace token

#endif //__TOKENIZATION_TOKEN_GENERATION_ERROR_HH__
