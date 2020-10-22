
#ifndef __TOKENIZATION_TOKEN_RANGE_ERROR_HH__
#define __TOKENIZATION_TOKEN_RANGE_ERROR_HH__

#include "exception.hh"

namespace token {
  namespace exceptions {
    class TokenRangeError : public TokenException {
     public:
      explicit TokenRangeError( std::string string )
        : TokenException( string ) {}
    };
  } // namespace exceptions
} // namespace token

#endif //__TOKENIZATION_TOKEN_RANGE_ERROR_HH__
