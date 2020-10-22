
#ifndef __TOKENIZATION_INVALID_TOKEN_FORMAT_HH__
#define __TOKENIZATION_INVALID_TOKEN_FORMAT_HH__

#include "exception.hh"

namespace token {
  namespace exceptions {
    class InvalidTokenFormat : public TokenException {
     public:
      explicit InvalidTokenFormat( std::string vault, size_t _format )
        : TokenException( std::string( "Token vault " ) + vault +
                          std::string( " configured with an invalid format" ) +
                          std::to_string( _format ) ) {}
    };
  } // namespace exceptions
} // namespace token

#endif //__TOKENIZATION_INVALID_TOKEN_FORMAT_HH__
