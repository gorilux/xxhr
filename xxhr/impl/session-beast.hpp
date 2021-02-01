#ifndef XXHR_DETAIL_SESSION_BEAST_HPP
#define XXHR_DETAIL_SESSION_BEAST_HPP

#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/trim_all.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <regex>
#include <string>
#include <utility>
#include <variant>
#include <xxhr/auth.hpp>
#include <xxhr/body.hpp>
#include <xxhr/cookies.hpp>
#include <xxhr/digest.hpp>
#include <xxhr/max_redirects.hpp>
#include <xxhr/multipart.hpp>
#include <xxhr/parameters.hpp>
#include <xxhr/response.hpp>
#include <xxhr/timeout.hpp>
#include <xxhr/xxhrtypes.hpp>
#include <xxhr/session.hpp>

namespace xxhr {



using tcp      = boost::asio::ip::tcp;  // from <boost/asio/ip/tcp.hpp>
namespace ssl  = boost::asio::ssl;      // from <boost/asio/ssl.hpp>
namespace http = boost::beast::http;    // from <boost/beast/http.hpp>

using plain_or_tls = std::variant<std::monostate, tcp::socket, ssl::stream<tcp::socket>>;

class Session::Impl : public std::enable_shared_from_this<Session::Impl> {
public:
    Impl();

    void SetUrl(const Url& url);
    void SetParameters(const Parameters& parameters);
    void SetParameters(Parameters&& parameters);
    void SetHeader(const Header& header);
    void SetTimeout(const Timeout& timeout);
    void SetAuth(const Authentication& auth);
    void SetDigest(Digest&& auth);

    void SetMultipart(Multipart&& multipart);
    void SetMultipart(const Multipart& multipart);
    void SetRedirect(const bool& redirect);
    void SetMaxRedirects(const MaxRedirects& max_redirects);
    void SetCookies(const Cookies& cookies, bool delete_them = false);
    void CookiesCleanup();

    //! Set the provided body of request
    void SetBody(const Body& body);

    template <class Handler>
    void SetHandler(const on_response_<Handler>&& functor) {
        on_response = functor;
    }

    void QUERY(http::verb method);

    void DELETE_();
    void GET();
    void HEAD();
    void OPTIONS();
    void PATCH();
    void POST();
    void PUT();    

private:
    bool is_tls_stream();

    ssl::stream<tcp::socket>& tls_stream();

    tcp::socket& plain_stream();
    void         fail(boost::system::error_code ec, xxhr::ErrorCode xxhr_ec);
    // Start the asynchronous operation
    void register_request();

    void on_resolve(boost::system::error_code ec, tcp::resolver::results_type results);

    void on_connect(boost::system::error_code ec);

    void on_stream_ready(boost::system::error_code ec);

    void on_write(boost::system::error_code ec, std::size_t bytes_transferred);

    void on_read(boost::system::error_code ec, std::size_t bytes_transferred);

    void on_shutdown(boost::system::error_code ec);

    void on_timeout(const boost::system::error_code& ec);
    bool generateAuthentication(boost::string_view authenticate);
    bool generateBasicAuthentication();
    bool generateDigestAuth(boost::string_view authenticate, boost::string_view body);

    void full_request(http::verb method);
    void do_one_request(http::verb method);

    util::url_parts                  url_parts_;
    std::string                      url_;
    Parameters                       parameters_;
    http::request<http::string_body> req_;
    std::chrono::milliseconds        timeout_             = std::chrono::milliseconds{0};
    bool                             redirect_            = true;
    bool                             follow_next_redirect = false;
    std::int32_t                     number_of_redirects  = std::numeric_limits<std::int32_t>::max();

    std::function<void(Response&&)> on_response;

    boost::asio::io_context   ioc;
    boost::asio::steady_timer timeouter{ioc};
    ssl::context              ctx{ssl::context::sslv23_client};
    tcp::resolver             resolver_{ioc};
    plain_or_tls              stream_;
    boost::beast::flat_buffer buffer_;  // (Must persist between reads)    
    Authentication            auth_;
    Digest                    digest_;

    std::shared_ptr<http::response_parser<http::string_body>> res_parser_ = std::make_shared<http::response_parser<http::string_body>>();

};


template <class Handler>
  void Session::SetOption(const on_response_<Handler>&& on_response) { 
    pimpl_->SetHandler(std::move(on_response)); 
  }


}  // namespace xxhr

#endif
