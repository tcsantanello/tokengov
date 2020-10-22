#ifndef __TOKEN_API_HH_
#define __TOKEN_API_HH_

#include "token/api/manager.hh"
#include "token/crypto.hh"

namespace token {
  namespace api {
    void                              register_logger( std::shared_ptr< spdlog::logger > logger );
    std::shared_ptr< spdlog::logger > create_logger( std::string name, std::vector< spdlog::sink_ptr > sinks );
  } // namespace api
} // namespace token

#endif // __TOKEN_API_HH_
