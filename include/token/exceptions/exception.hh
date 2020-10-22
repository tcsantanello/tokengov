
#ifndef __TOKENIZATION_EXCEPTION_HH__
#define __TOKENIZATION_EXCEPTION_HH__

#include <exception>
#include <string>

namespace token {
  namespace exceptions {
    class TokenException : public std::exception {
      const std::string message;

     public:
      explicit TokenException( const std::string &msg )
        : message( msg ) {}

      const char *what( ) const noexcept override { return message.c_str( ); }
    };
  } // namespace exceptions
} // namespace token

#endif //__TOKENIZATION_EXCEPTION_HH__
