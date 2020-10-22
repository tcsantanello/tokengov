
#include "luhn.hh"
#include "token/api.hh"

#include <cctype>
#include <functional>
#include <stdio.h>

namespace token {
  namespace api {
    std::string generateRandom( const TokenManager::RandBytes &rand,
                                const std::string &            value,
                                std::string *                  mask,
                                bool                           upper,
                                bool                           lower,
                                bool                           digits,
                                bool                           punct ) {
      static char NUMERICS[] = "0123456789";
      static char UPPER[]    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      static char LOWER[]    = "abcdefghijklmnopqrstuvwxyz";
      static char PUNCT[]    = "!@#$%^&*()-=_+{}[]:\";\'<>?,./";

      std::stringstream ss;
      std::string       token;
      uint8_t           bytes[ 256 ] = "";
      uint8_t *         pbytes       = nullptr;
      uint8_t *         pend         = nullptr;
      uint8_t           block[ 100 ] = "";
      uint8_t *         pblock       = block;
      int               attempts     = 0;

      if ( digits ) {
        memcpy( pblock, NUMERICS, sizeof( NUMERICS ) - 1 );
        pblock += sizeof( NUMERICS ) - 1;
      }

      if ( upper ) {
        memcpy( pblock, UPPER, sizeof( UPPER ) - 1 );
        pblock += sizeof( UPPER ) - 1;
      }

      if ( lower ) {
        memcpy( pblock, LOWER, sizeof( LOWER ) - 1 );
        pblock += sizeof( LOWER ) - 1;
      }

      if ( punct ) {
        memcpy( pblock, PUNCT, sizeof( PUNCT ) - 1 );
        pblock += sizeof( PUNCT ) - 1;
      }

      do {
        if ( ++attempts > 3 ) {
          throw exceptions::TokenGenerationError( "Too many token generation attempts" );
        }

        pbytes = bytes;
        pend   = bytes + std::min( sizeof( bytes ), value.size( ) );
        rand( bytes, pend - bytes );

        ss.str( "" );
        ss.clear( );

        for ( auto &ch : value ) {
          if ( ( ( ::isdigit( ch ) != 0 ) && ( digits ) ) ||
               ( ( ::isupper( ch ) != 0 ) && ( upper ) ) ||
               ( ( ::islower( ch ) != 0 ) && ( lower ) ) ||
               ( ( ::ispunct( ch ) != 0 ) && ( punct ) ) ) {
            if ( pbytes == pend ) {
              pbytes = bytes;
              pend   = bytes + std::min( sizeof( bytes ), value.size( ) );
              rand( bytes, pend - bytes );
            }

            ss << block[ *( pbytes++ ) % ( pblock - block ) ];
          }
        }
      } while ( ss.str( ) == value );

      token = ss.str( );

      if ( mask != nullptr ) {
        ss.str( "" );
        ss.clear( );

        for ( std::string::size_type num = 0; num < value.size( ); ++num ) {
          ss << "*";
        }

        *mask = ss.str( );
      }

      return token;
    }

    std::string generateFPR( const TokenManager::RandBytes &rand,
                             const std::string &            value,
                             std::string *                  mask ) {
      bool upper  = false;
      bool lower  = false;
      bool digits = false;

      for ( auto &ch : value ) {
        if ( ::isdigit( ch ) != 0 ) {
          digits = true;
        } else if ( ::isalpha( ch ) != 0 ) {
          if ( ::isupper( ch ) != 0 ) {
            upper = true;
          } else {
            lower = true;
          }
        }

        if ( ( digits ) && ( upper ) && ( lower ) ) {
          break;
        }
      }

      return generateRandom( rand, value, mask, upper, lower, digits, false );
    }

    std::string generatePreserved( const TokenManager::RandBytes &rand,
                                   const std::string &            value,
                                   std::string *                  mask,
                                   size_t                         front,
                                   size_t                         back,
                                   bool                           passLuhn ) {
      if ( ( front + back ) >= value.size( ) ) {
        std::stringstream ss;
        ss << "Preserved lengths ";
        ss << front << " " << back;
        ss << ", exceed the length of the value to tokenize";

        throw exceptions::TokenRangeError( ss.str( ) );
      }

      auto length = value.size( ) - back - front;

      do {
        std::stringstream ss;
        std::string       tmp;

        ss << value.substr( 0, front );
        ss << generateRandom(
          rand, value.substr( front, length ), nullptr, false, false, true, false );
        ss << value.substr( front + length );
        tmp = ss.str( );

        if ( passLuhn == luhn::check( tmp ) ) {
          if ( mask != nullptr ) {
            ss.str( "" );
            ss.clear( );

            ss << value.substr( 0, front );

            for ( size_t num = 0; num < length; ++num ) {
              ss << "*";
            }

            ss << value.substr( front + length );

            *mask += ss.str( );
          }
          return tmp;
        }
      } while ( true );
    }

    TokenManager::GeneratorMap TokenManager::generators{
      { TokenManager::RANDOM_FORMAT,
        std::bind( generateRandom,
                   std::placeholders::_1,
                   std::placeholders::_2,
                   std::placeholders::_3,
                   true,
                   true,
                   true,
                   true ) },
      { TokenManager::FP_RANDOM_FORMAT, generateFPR },
      { TokenManager::DATE_FORMAT,
        std::bind( generateRandom,
                   std::placeholders::_1,
                   std::placeholders::_2,
                   std::placeholders::_3,
                   false,
                   false,
                   true,
                   false ) },
      { TokenManager::EMAIL_FORMAT,
        std::bind( generateRandom,
                   std::placeholders::_1,
                   std::placeholders::_2,
                   std::placeholders::_3,
                   true,
                   true,
                   false,
                   false ) },
      { TokenManager::L4_FORMAT,
        std::bind( generatePreserved,
                   std::placeholders::_1,
                   std::placeholders::_2,
                   std::placeholders::_3,
                   0,
                   4,
                   true ) },
      { TokenManager::F6_FORMAT,
        std::bind( generatePreserved,
                   std::placeholders::_1,
                   std::placeholders::_2,
                   std::placeholders::_3,
                   6,
                   0,
                   true ) },
      { TokenManager::F6L4_FORMAT,
        std::bind( generatePreserved,
                   std::placeholders::_1,
                   std::placeholders::_2,
                   std::placeholders::_3,
                   6,
                   4,
                   true ) },
      { TokenManager::F2L4_FORMAT,
        std::bind( generatePreserved,
                   std::placeholders::_1,
                   std::placeholders::_2,
                   std::placeholders::_3,
                   2,
                   4,
                   true ) },
      { TokenManager::L4_NOLUHN_FORMAT,
        std::bind( generatePreserved,
                   std::placeholders::_1,
                   std::placeholders::_2,
                   std::placeholders::_3,
                   0,
                   4,
                   false ) },
      { TokenManager::F6_NOLUHN_FORMAT,
        std::bind( generatePreserved,
                   std::placeholders::_1,
                   std::placeholders::_2,
                   std::placeholders::_3,
                   6,
                   0,
                   false ) },
      { TokenManager::F6L4_NOLUHN_FORMAT,
        std::bind( generatePreserved,
                   std::placeholders::_1,
                   std::placeholders::_2,
                   std::placeholders::_3,
                   6,
                   4,
                   false ) },
      { TokenManager::F2L4_NOLUHN_FORMAT,
        std::bind( generatePreserved,
                   std::placeholders::_1,
                   std::placeholders::_2,
                   std::placeholders::_3,
                   2,
                   4,
                   false ) },
    };
  } // namespace api
} // namespace token
