#include "token/api.hh"

#include <spdlog/spdlog.h>

#include <spdlog/sinks/null_sink.h>

namespace token {
  namespace api {
    /**
     * @brief Create and register a logger with the library's spdlog
     * @param name logger name
     * @param sinks logger targets/sinks
     */
    std::shared_ptr< spdlog::logger > create_logger( std::string name, std::vector< spdlog::sink_ptr > sinks ) {
      std::shared_ptr< spdlog::logger > logger = spdlog::get( name );

      if ( !logger ) {
        if ( sinks.empty( ) ) {
          sinks.emplace_back( std::make_shared< spdlog::sinks::null_sink_mt >( ) );
        }

        logger = std::make_shared< spdlog::logger >( name, sinks.begin( ), sinks.end( ) );

        spdlog::register_logger( logger );
      } else {
        auto &lsinks = logger->sinks( );

        std::copy( sinks.begin( ), sinks.end( ), std::back_inserter( lsinks ) );
        std::sort( lsinks.begin( ), lsinks.end( ) );

        lsinks.erase( std::unique( lsinks.begin( ), lsinks.end( ) ), lsinks.end( ) );
      }

      return logger;
    }
  } // namespace api
} // namespace token
