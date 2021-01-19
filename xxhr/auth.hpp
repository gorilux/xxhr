#ifndef XXHR_AUTH_H
#define XXHR_AUTH_H

#include <string>

#include "defines.hpp"

namespace xxhr {

/**
 * \brief Some Web APIs requires authenticating via HTTP Basic auth ( *i.e.* base64 encoded user and password authentication).
 *
 * \copydoc authentication-cpp
 *
 */

struct Authentication
{
  std::string username;
  std::string password;
};
// class Authentication {
// public:
//     Authentication() {}

//     //! Specify username and password for basic auth
//     template <typename UserType, typename PassType>
//     Authentication(UserType&& username, PassType&& password)
//         : username_{XXHR_FWD(username)}, password_{XXHR_FWD(password)}, auth_string_{username_ + ":" + password_} {}

//     std::string GetAuthString() const noexcept { return auth_string_; }

//     //!
//     std::string username() const { return username_; }
//     //!
//     std::string password() const { return password_; }

// private:
//     std::string username_;
//     std::string password_;
//     std::string auth_string_;
// };

}  // namespace xxhr

#endif
