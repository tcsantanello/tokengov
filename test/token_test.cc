
#include "osslprovider.hh"
#include "pgsqldb.hh"
#include "sqlitedb.hh"
#include <algorithm>
#include <assert.h>
#include <iostream>
#include <unistd.h>

#include <spdlog/sinks/stdout_color_sinks.h>

#define SQLITE3_DB "sqlite3.db"
#define SQLITE3URI "sqlite://" SQLITE3_DB
#define PSQLURI "psql://" POSTGRESQL_USERNAME ":" POSTGRESQL_PASSWORD "@" POSTGRESQL_HOSTNAME "/" POSTGRESQL_DATABASE

bool OpenSSLProvider::randomize = true;
int  OpenSSLProvider::cycle     = 10;

static void basic( token::api::TokenManager &tm, const std::string &vault, const std::string &value ) {
  token::api::TokenEntry entry;

  entry.properties = { { "property", "value" } };

  auto tokEntry = tm.tokenize( vault, value, &entry );
  auto detEntry = tm.detokenize( vault, tokEntry.token );

  std::cout << __PRETTY_FUNCTION__ << "\n";

  std::cout << "------------- Parameters ----------------\n";
  std::cout << "Vault: " << vault << "\n";
  std::cout << "Value: " << value << "\n";
  std::cout << "------------ Tokenization ---------------\n";
  std::cout << "Token: " << tokEntry.token << "\n";
  std::cout << "Value: " << tokEntry.value << "\n";
  for ( auto &pair : tokEntry.properties ) {
    std::cout << pair.first << ": " << pair.second << "\n";
  }

  std::cout << "----------- Detokenization --------------\n";
  std::cout << "Token: " << detEntry.token << "\n";
  std::cout << "Value: " << detEntry.value << "\n";
  for ( auto &pair : detEntry.properties ) {
    std::cout << pair.first << ": " << pair.second << "\n";
  }
}

static void duplicateFail( token::api::TokenManager &tm, const std::string &vault, const std::string &value ) {
  token::api::TokenEntry tokEntry;

  std::cout << __PRETTY_FUNCTION__ << "\n";

  try {
    OpenSSLProvider::randomize = false;

    tokEntry = tm.tokenize( vault, value, nullptr );

    OpenSSLProvider::cycle = 10;

    tokEntry = tm.tokenize( vault, value, nullptr );
  } catch ( std::exception &ex ) {
    std::cout << ex.what( ) << "\n";

    return;
  }

  assert( false );
}

static void duplicatePass( token::api::TokenManager &tm, const std::string &vault, const std::string &value ) {
  token::api::TokenEntry tokEntry;

  std::cout << __PRETTY_FUNCTION__ << "\n";

  try {
    OpenSSLProvider::randomize = false;
    OpenSSLProvider::cycle     = 5;
    tokEntry.properties        = { { "property", "value" } };

    tokEntry = tm.tokenize( vault, value, &tokEntry );
  } catch ( std::exception &ex ) {
    std::cout << ex.what( ) << "\n";
    assert( false );
  }

  std::cout << "------------- Parameters ----------------\n";
  std::cout << "Vault: " << vault << "\n";
  std::cout << "Value: " << value << "\n";
  std::cout << "------------ Tokenization ---------------\n";
  std::cout << "Token: " << tokEntry.token << "\n";
  std::cout << "Value: " << tokEntry.value << "\n";

  for ( auto &pair : tokEntry.properties ) {
    std::cout << pair.first << ": " << pair.second << "\n";
  }
}

static void duplicateDurable( token::api::TokenManager &tm, const std::string &vault, const std::string &value ) {
  token::api::TokenEntry entryOne;
  token::api::TokenEntry entryTwo;

  std::cout << __PRETTY_FUNCTION__ << "\n";

  try {
    entryOne.properties = { { "property", "value" } };

    entryOne = tm.tokenize( vault, value, nullptr );
    entryTwo = tm.tokenize( vault, value, nullptr );

    assert( entryOne.token == entryTwo.token );

    std::cout << "------------- Parameters ----------------\n";
    std::cout << "Vault: " << vault << "\n";
    std::cout << "Value: " << value << "\n";
    std::cout << "------------ Tokenization ---------------\n";
    std::cout << "Token: " << entryOne.token << "\n";
    std::cout << "Value: " << entryOne.value << "\n";

    for ( auto &pair : entryOne.properties ) {
      std::cout << pair.first << ": " << pair.second << "\n";
    }

  } catch ( std::exception &ex ) {
    std::cout << ex.what( ) << "\n";
    assert( false );
  }
}

bool doRemove = false;

static void remove( token::api::TokenManager &tm, const std::string &vault, const std::string &value ) {
  std::cout << __PRETTY_FUNCTION__ << "\n";

  if ( doRemove ) {
    auto retEntries = tm.retrieve( vault, value );

    for ( auto &&retEntry : retEntries ) {
      auto remEntry = tm.remove( vault, retEntry.token );

      std::cout << "-------------- Removal ------------------\n";
      std::cout << "Token: " << remEntry.token << "\n";
      std::cout << "Value: " << remEntry.value << "\n";

      for ( auto &pair : remEntry.properties ) {
        std::cout << pair.first << ": " << pair.second << "\n";
      }
    }
  }
}

template < class DB >
static void run_tests( const std::string &uri ) {
  token::api::TokenManager tm( std::make_shared< OpenSSLProvider >( ), std::make_shared< DB >( uri, 10 ) );
  std::string              value         = "6044342464567232";
  auto                     transactional = { remove, basic, duplicateFail, duplicatePass, remove };
  auto                     durable       = { remove, basic, duplicateDurable, remove };

  tm.createVault( "transactional", "ENCKEY!!!", "MACKEY!!!", 7, 20, false );
  tm.createVault( "durable", "ENCKEY!!!", "MACKEY!!!", 7, 20, true );

  try {
    std::cout << "==========================================================\n"
              << uri << "\n"
              << "==========================================================\n";

    for ( auto &method : transactional ) {
      std::cout << "--------------------------------------------------------"
                << "\n";
      method( tm, "transactional", value );
    }

    for ( auto &method : durable ) {
      std::cout << "--------------------------------------------------------"
                << "\n";
      method( tm, "durable", value );
    }
  } catch ( std::exception &ex ) {
    std::cout << ex.what( ) << "\n";
    assert( false );
  }
}

void log_init( void ) {
  auto        sink    = std::make_shared< spdlog::sinks::stdout_color_sink_mt >( );
  std::string names[] = {
    "dbcpp::psql", "dbcpp::sqlite", "dbcpp::Pool", "dbcpp::Driver", "token::api::manager", "token::api::tokendb" };

  for ( auto &&name : names ) {
    token::api::create_logger( name, { sink } )->set_level( spdlog::level::trace );
  }
}

int main( int argc, char *argv[] ) {
  doRemove = argc == 1;

  log_init( );

  run_tests< SQLiteDB >( SQLITE3URI );
  unlink( SQLITE3_DB );

  run_tests< PgSqlDB >( PSQLURI );

  return 0;
}
