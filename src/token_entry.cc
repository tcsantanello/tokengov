
#include "token/api.hh"
#include <iostream>
#include <nlohmann/json.hpp>

namespace token {
  namespace api {
    using map_t = std::map< std::string, std::string >;

    bytea TokenEntry::serialize( const map_t &map ) { return nlohmann::json::to_cbor( nlohmann::json{ map } ); }

    map_t TokenEntry::deserialize( const bytea &bytes ) {
      map_t result{ };
      auto  json = nlohmann::json::from_cbor( bytes );

      for ( auto &entry : json[ 0 ].items( ) ) {
        result[ entry.key( ) ] = entry.value( ).get< std::string >( );
      }

      return result;
    }
  } // namespace api
} // namespace token
