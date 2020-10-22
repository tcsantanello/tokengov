
SET( SOURCES
  generators.cc
  logger.cc
  token_db.cc
  token_entry.cc
  token_manager.cc
  )

MESSAGE( STATUS "Sources: ${SOURCES}" )

ADD_LIBRARY( tokengov SHARED ${SOURCES} )

TARGET_LINK_LIBRARIES( tokengov
  ${Boost_THREAD_LIBRARY}
  ${Boost_SYSTEM_LIBRARY}
  ${CONAN_LIBS_FMT}
  ${CONAN_LIBS_SPDLOG}
  ${CONAN_LIBS_DBCPP}
)
