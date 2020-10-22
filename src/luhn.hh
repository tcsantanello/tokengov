#ifndef __LUHN_HH_
#define __LUHN_HH_

#include <iterator>
#include <numeric>
#include <stdexcept>
#include <stdint.h>

namespace token {
  namespace luhn {
    struct LuhnSum {
      bool even = false;

      int operator( )( int val, char ch ) {
        static const uint16_t values[][ 10 ] = { { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 },
                                                 { 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 } };
        even                                 = !even;
        return val + values[ even ][ ch - '0' ];
      }
    };

    template < typename Iter >
    uint16_t calculate( Iter begin, Iter end ) {
      uint16_t v = std::accumulate( std::reverse_iterator< Iter >( end ),
                                    std::reverse_iterator< Iter >( begin ),
                                    0,
                                    LuhnSum( ) );
      return v;
    }

    template < typename T >
    uint16_t calculate( T value ) {
      return calculate( std::begin( value ), std::end( value ) );
    }

    template < typename Iter >
    uint16_t generate( Iter begin, Iter end ) {
      return 10 - ( calculate( begin, end ) % 10 );
    }

    template < typename T >
    uint16_t generate( T value ) {
      return generate( std::begin( value ), std::end( value ) );
    }

    template < typename Iter >
    bool check( Iter begin, Iter end ) {
      if ( begin != end ) {
        return *end == generate( begin, end ) + '0';
      }
      return false;
    }

    template < typename T >
    bool check( T value ) {
      return check( std::begin( value ), std::end( value ) - 1 );
    }
  } // namespace luhn
} // namespace token

#endif
