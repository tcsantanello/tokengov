
#include "token/api.hh"
#include <sstream>

#define LOG( lvl, fmt, ... )                                                                       \
  do {                                                                                             \
    if ( dblogger->should_log( spdlog::level::lvl ) ) {                                            \
      dblogger->lvl( fmt, ##__VA_ARGS__ );                                                         \
    }                                                                                              \
  } while ( 0 )

namespace token {
  namespace api {
    namespace core {
      static constexpr auto NO_TIME  = dbcpp::DBTime( std::chrono::seconds( 0 ) );
      static auto           HASH_LIT = std::string{ "hash" };

      /** Datasource logger */
      std::shared_ptr< spdlog::logger > dblogger =
        token::api::create_logger( "token::api::tokendb", { } );

      TokenEntry TokenDB::get( const std::string &tableName, const std::string &token ) {
        TokenEntry entry;

        LOG( debug, "Getting entry for token {} from table {}", token, tableName );

        auto connection = dbPool.getConnection( );
        auto statement  = connection << ( "SELECT * FROM " + tableName + " WHERE token = ?" )
                                    << token;
        auto rs = statement.executeQuery( );

        if ( rs.next( ) ) {
          LOG( debug, "Successfully retrieved record for {} from {}", token, tableName );
          entry.load( rs );
        } else {
          LOG( debug, "No record found for {} from {}", token, tableName );
        }

        return entry;
      }

      std::vector< TokenEntry > TokenDB::get( const std::string &tableName, const bytea &hmac ) {
        std::vector< TokenEntry > entries;
        LOG( debug, "Performing hash lookup in table {}", tableName );

        auto connection = dbPool.getConnection( );
        auto statement = connection << ( "SELECT * FROM " + tableName + " WHERE hmac = ?" ) << hmac;
        auto rs        = statement.executeQuery( );

        while ( rs.next( ) ) {
          entries.emplace_back( TokenEntry( rs ) );
        }

        LOG( debug,
             "Successfully retrieved {} record{} from {}",
             entries.size( ),
             entries.size( ) > 1 ? "s" : "",
             tableName );

        return entries;
      }

      void TokenDB::insert( const std::string &tableName, const TokenEntry &entry ) {
        auto connection = dbPool.getConnection( );

        std::stringstream ss;
        dbcpp::Statement  statement;

        LOG( debug, "Inserting record for token {} into table {}", entry.token, tableName );

        ss << "INSERT INTO " << tableName << "( ";

        if ( entry.encKey.length( ) > 0 ) {
          ss << "ENCKEY, ";
        }

        ss << "TOKEN, HMAC, CRYPT, MASK, EXPIRATION, PROPERTIES ) VALUES ( ";

        if ( entry.encKey.length( ) > 0 ) {
          ss << "?, ";
        }

        ss << "?, ?, ?, ?, ?, ? )";

        statement = connection << ss.str( );

        if ( entry.encKey.length( ) > 0 ) {
          statement << entry.encKey;
        }

        statement << entry.token << entry.hmac << entry.crypt << entry.mask << entry.expiration
                  << TokenEntry::serialize( entry.properties );

        if ( statement.executeUpdate( ) != 1 ) {
          LOG( debug, "Failed to insert {} record into {}", entry.token, tableName );
          throw exceptions::TokenSQLError( "Unable to insert token into tableName" );
        }

        LOG( debug, "Successfully inserted {} record into {}", entry.token, tableName );

        connection.commit( );
      }

      void TokenDB::remove( const std::string &tableName, TokenEntry &entry ) {
        auto connection = dbPool.getConnection( );

        if ( ( entry.token.empty( ) ) && ( entry.hmac.empty( ) ) ) {
          LOG( warn, "No token or hmac supplied for removal operation from {}", tableName );

          throw exceptions::TokenSQLError(
            "Unable to remove token, no unique/identifer values (token, or hmac)" );
        }

        LOG( debug,
             "Preparing to remove {} record from {}",
             entry.token.empty( ) ? entry.token : HASH_LIT,
             tableName );

        {
          LOG( debug,
               "Performing final retrieve of {} record from {}",
               entry.token.empty( ) ? entry.token : HASH_LIT,
               tableName );

          auto statement = connection << ( "SELECT * FROM " + tableName + " WHERE token = ?" )
                                      << entry.token;
          auto rs = statement.executeQuery( );

          if ( rs.next( ) ) {
            LOG( debug,
                 "Successfully retrieved record {} from {}",
                 entry.token.empty( ) ? entry.token : HASH_LIT,
                 tableName );
            entry.load( rs );
          }
        }

        dbcpp::Statement statement;

        if ( !entry.token.empty( ) ) {
          LOG( debug, "Remove {} record from {} by token", entry.token, tableName );
          statement = connection << ( "DELETE FROM " + tableName + " WHERE token = ?" )
                                 << entry.token;
        } else if ( !entry.hmac.empty( ) ) {
          LOG( debug, "Remove hash record from {}", tableName );
          statement = connection << ( "DELETE FROM " + tableName + " WHERE hmac = ?" )
                                 << entry.hmac;
        }

        if ( statement.executeUpdate( ) != 1 ) {
          LOG( debug, "Unable to remove non-existant record from {}", tableName );
          throw exceptions::TokenSQLError( "Unable to remove token, entry does not exist" );
        }

        LOG( debug, "Successfully removed record from {}", tableName );

        connection.commit( );
      }

      void TokenDB::update( const std::string &tableName, TokenEntry &entry ) {
        std::stringstream ss;
        dbcpp::Statement  statement;
        auto              connection = dbPool.getConnection( );
        auto              fieldSet   = false;

        ss << "UPDATE " << tableName << " SET ";

        if ( entry.token.empty( ) ) {
          return;
        }

        if ( !entry.encKey.empty( ) ) {
          ss << "ENCKEY = ?";
          fieldSet = true;
        }

        if ( !entry.hmac.empty( ) ) {
          if ( fieldSet ) {
            ss << ", ";
          }

          ss << "HMAC = ?";
          fieldSet = true;
        }

        if ( !entry.crypt.empty( ) ) {
          if ( fieldSet ) {
            ss << ", ";
          }

          ss << "CRYPT = ?";
          fieldSet = true;
        }

        if ( !entry.mask.empty( ) ) {
          if ( fieldSet ) {
            ss << ", ";
          }

          ss << "MASK = ?";
          fieldSet = true;
        }

        if ( entry.expiration != NO_TIME ) {
          if ( fieldSet ) {
            ss << ", ";
          }

          ss << "EXPIRATION = ?";
          fieldSet = true;
        }

        if ( !entry.properties.empty( ) ) {
          if ( fieldSet ) {
            ss << ", ";
          }

          ss << "PROPERTIES = ?";
          fieldSet = true;
        }

        if ( !fieldSet ) {
          return;
        }

        ss << " WHERE token = ?";

        statement = connection << ss.str( );

        if ( !entry.encKey.empty( ) ) {
          statement << entry.encKey;
        }

        if ( !entry.hmac.empty( ) ) {
          statement << entry.hmac;
        }

        if ( !entry.crypt.empty( ) ) {
          statement << entry.crypt;
        }

        if ( !entry.mask.empty( ) ) {
          statement << entry.mask;
        }

        if ( entry.expiration != NO_TIME ) {
          statement << entry.expiration;
        }

        if ( !entry.properties.empty( ) ) {
          statement << TokenEntry::serialize( entry.properties );
        }

        LOG( debug, "Performing record update for {} in table {}", entry.token, tableName );

        if ( statement.executeUpdate( ) == 0 ) {
          LOG( debug, "Error encountered updating record for {}: not found", entry.token );
          throw exceptions::TokenSQLError( "Error updating record for token: " + entry.token );
        }

        connection.commit( );

        LOG( debug, "Getting updated entry for token {} from table {}", entry.token, tableName );

        statement = connection << ( "SELECT * FROM " + tableName + " WHERE token = ?" )
                               << entry.token;
        auto rs = statement.executeQuery( );

        if ( rs.next( ) ) {
          LOG( debug, "Successfully retrieved record for {} from {}", entry.token, tableName );
          entry.load( rs );
        }
      }

      static void queryAddSet( std::stringstream &ss, const std::string &field, size_t count ) {
        if ( count > 0 ) {
          if ( !ss.str( ).empty( ) ) {
            ss << " AND ";
          }

          ss << field << " IN ( ";

          for ( size_t num = 0;; ) {
            ss << "?";

            if ( ++num >= count ) {
              break;
            }

            ss << ", ";
          }

          ss << " )";
        }
      }

      std::vector< TokenEntry > TokenDB::query( const std::string &                 tableName,
                                                const std::vector< std::string > &  tokens,
                                                const std::vector< bytea > &        hmacs,
                                                const std::vector< dbcpp::DBTime > &expirations,
                                                std::string                         sortField,
                                                bool                                sortAsc,
                                                size_t                              offset,
                                                size_t                              limit,
                                                size_t *                            recordCount ) {
        std::vector< TokenEntry > rc;
        std::string::size_type    orderByIndex = 0;
        dbcpp::Statement          statement;
        std::stringstream         build;
        std::stringstream         where;
        std::string               query;
        auto                      connection = dbPool.getConnection( );

        if ( sortField.empty( ) ) {
          sortField = "creation_date";
        }

        build << "SELECT * FROM " << tableName;

        queryAddSet( where, "token", tokens.size( ) );
        queryAddSet( where, "hmac", hmacs.size( ) );
        queryAddSet( where, "expiration", expirations.size( ) );

        if ( !where.str( ).empty( ) ) {
          build << " WHERE " << where.str( );
        }

        orderByIndex = build.str( ).size( );

        build << " ORDER BY " << sortField << ( sortAsc ? " ASC " : " DESC " );

        if ( offset != 0 ) {
          build << " OFFSET " << offset;
        }

        if ( limit != 0 ) {
          build << " LIMIT " << limit;
        }

        query     = build.str( );
        statement = connection << query;

        for ( auto &token : tokens ) {
          statement << token;
        }

        for ( auto &hmac : hmacs ) {
          statement << hmac;
        }

        for ( auto &expiry : expirations ) {
          statement << expiry;
        }

        for ( auto rs = statement.executeQuery( ); rs.next( ); ) {
          rc.emplace_back( TokenEntry( rs ) );
        }

        if ( recordCount != nullptr ) {
          query     = "SELECT COUNT(0) " + query.substr( 8, orderByIndex - 8 );
          statement = connection << query;
          for ( auto &token : tokens ) {
            statement << token;
          }

          for ( auto &hmac : hmacs ) {
            statement << hmac;
          }

          for ( auto &expiry : expirations ) {
            statement << expiry;
          }

          auto rs = statement.executeQuery( );

          if ( !rs.next( ) ) {
            throw exceptions::TokenSQLError( "Failure executing count query: " + query );
          }

          *recordCount = rs.get< size_t >( 0 );
        }

        return rc;
      }

      bool TokenDB::updateKey( SharedVault vault, const std::string &encKey ) {
        auto connection = dbPool.getConnection( );
        auto statement  = connection << "UPDATE vaults SET enckey = ? WHERE tablename = ?" << encKey
                                    << vault->table;
        auto rc = statement.executeUpdate( );
        connection.commit( );
        return rc;
      }

      bool TokenDB::updateKey( const std::string &vault, const std::string &encKey ) {
        auto connection = dbPool.getConnection( );
        auto statement  = connection
                         << "UPDATE vaults SET enckey = ? WHERE ? IN ( alias, tablename )" << encKey
                         << vault;
        auto rc = statement.executeUpdate( );
        connection.commit( );
        return rc;
      }

      bool TokenDB::rekey( SharedVault vault, const std::string &encKey, recrypt_type recrypt ) {
        try {
          auto connection = dbPool.getConnection( );
          auto statement = connection << fmt::format( "SELECT * FROM {} FOR UPDATE", vault->table );
          auto results   = statement.executeQuery( );
          std::string query[] = {
            fmt::format( "UPDATE {} SET crypt = ? WHERE hmac = ?", vault->table ),
            fmt::format( "UPDATE {} SET enckey = ?, crypt = ? WHERE hmac = ?", vault->table ) };
          while ( results.next( ) ) {
            TokenEntry entry( results );
            auto       ret = recrypt( encKey, //
                                !entry.encKey.empty( ) ? entry.encKey : vault->encKeyName,
                                entry.crypt );

            if ( !ret.empty( ) ) {
              auto stmt = connection << query[ !entry.encKey.empty( ) ];

              if ( !entry.encKey.empty( ) ) {
                stmt << encKey;
              }

              stmt << ret;
              stmt << entry.hmac;

              if ( !stmt.executeUpdate( ) ) {
                LOG( critical, "Failed to update previously selected record for {}", entry.mask );
                return false;
              }
            }
          }

          connection.commit( );
        } catch ( std::exception &ex ) {
          LOG( critical,
               "Failure encountered while processing rekey on {}: {}",
               vault->alias,
               ex.what( ) );
          return false;
        }

        return true;
      }
    } // namespace core
  }   // namespace api
} // namespace token
