
#ifndef __TOKENIZATION_TOKEN_SQL_ERROR_HH__
#define __TOKENIZATION_TOKEN_SQL_ERROR_HH__

#include "exception.hh"

namespace token {
  namespace exceptions {
    class TokenSQLError : public TokenException {
     public:
      explicit TokenSQLError( std::string string )
        : TokenException( string ) {}
    };
  } // namespace exceptions
} // namespace token

#endif //__TOKENIZATION_TOKEN_SQL_ERROR_HH__
