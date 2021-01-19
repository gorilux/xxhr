#ifndef XXHR_DETAIL_SESSION_HPP
#define XXHR_DETAIL_SESSION_HPP

#include <xxhr/session.hpp>

#if defined(__EMSCRIPTEN__)
  #include <xxhr/impl/session-emscripten.hpp> // Browser javascript implementation
#else
  #include <xxhr/impl/session-beast.hpp> // boost asio beast implementation
#endif

#endif
