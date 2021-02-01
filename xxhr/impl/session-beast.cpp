#include "session-beast.hpp"

#include <variant>

namespace xxhr {

using tcp      = boost::asio::ip::tcp;  // from <boost/asio/ip/tcp.hpp>
namespace ssl  = boost::asio::ssl;      // from <boost/asio/ssl.hpp>
namespace http = boost::beast::http;    // from <boost/beast/http.hpp>


using plain_or_tls = std::variant<std::monostate, tcp::socket, ssl::stream<tcp::socket>>;


Session::Impl::Impl(){

}

bool Session::Impl::is_tls_stream() {
    return std::holds_alternative<ssl::stream<tcp::socket>>(stream_);
}

ssl::stream<tcp::socket>& Session::Impl::tls_stream() {
    return std::get<ssl::stream<tcp::socket>>(stream_);
}

tcp::socket& Session::Impl::plain_stream() {
    return std::get<tcp::socket>(stream_);
}

void Session::Impl::fail(boost::system::error_code ec, xxhr::ErrorCode xxhr_ec) {
    //TODO: if (trace)
    std::cerr << ec << ": " << ec.message() << " distilled into : " << uint32_t(xxhr_ec) << "\n";

    on_response(xxhr::Response(
        0,  // 0 for errors which are on the layer belows http, like XmlHttpRequest.
        Error{xxhr_ec},
        std::string{},
        Header{},
        url_,
        Cookies{}));
}

// Start the asynchronous operation
void Session::Impl::register_request() {
    if (is_tls_stream()) {
        auto& stream = tls_stream();

        // Set SNI Hostname (many hosts need this to handshake successfully)
        // XXX: openssl specificae, abstract this shit please
        if (!SSL_set_tlsext_host_name(stream.native_handle(), url_parts_.host.data())) {
            boost::system::error_code ec{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()};
            std::cerr << ec.message() << "\n";
            return;
        }
    }

    // Look up the domain name
    resolver_.async_resolve(
        url_parts_.host.data(),
        url_parts_.port.data(),
        std::bind(
            &Session::Impl::on_resolve,
            shared_from_this(),
            std::placeholders::_1,
            std::placeholders::_2));
}

void Session::Impl::on_resolve(boost::system::error_code ec, tcp::resolver::results_type results) {
    if (ec)
        return fail(ec, ErrorCode::HOST_RESOLUTION_FAILURE);

    // Make the connection on the IP address we get from a lookup
    tcp::socket* socket;
    if (is_tls_stream()) {
        socket = &tls_stream().next_layer();
    } else {
        socket = &plain_stream();
    }

    boost::asio::async_connect(
        *socket,
        results.begin(),
        results.end(),
        std::bind(
            &Session::Impl::on_connect,
            shared_from_this(),
            std::placeholders::_1));
}

void Session::Impl::on_connect(boost::system::error_code ec) {
    if (ec)
        return fail(ec, ErrorCode::CONNECTION_FAILURE);

    if (is_tls_stream()) {
        // Perform the SSL handshake
        auto& stream = tls_stream();
        stream.async_handshake(
            ssl::stream_base::client,
            std::bind(
                &Session::Impl::on_stream_ready,
                shared_from_this(),
                std::placeholders::_1));
    } else {
        // Plain HTTP
        // consider handshake was performed.
        on_stream_ready(ec);
    }
}

void Session::Impl::on_stream_ready(boost::system::error_code ec) {
    if (ec)
        return fail(ec, ErrorCode::SSL_CONNECT_ERROR);

    // Send the HTTP request to the remote host
    std::visit([this](auto& stream) {
        if constexpr (std::is_same_v<std::monostate, std::decay_t<decltype(stream)>>)
            return;
        else {
            http::async_write(stream, req_,
                              std::bind(
                                  &Session::Impl::on_write,
                                  shared_from_this(),
                                  std::placeholders::_1,
                                  std::placeholders::_2));
        }
    },
               stream_);
}

void Session::Impl::on_write(boost::system::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec)
        return fail(ec, ErrorCode::NETWORK_SEND_FAILURE);

    // Receive the HTTP response
    std::visit([this](auto& stream) {
        if constexpr (std::is_same_v<std::monostate, std::decay_t<decltype(stream)>>)
            return;
        else {
            http::async_read(stream, buffer_, *res_parser_,
                             std::bind(
                                 &Session::Impl::on_read,
                                 shared_from_this(),
                                 std::placeholders::_1,
                                 std::placeholders::_2));
        }
    },
               stream_);
}

void Session::Impl::on_read(boost::system::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    timeouter.cancel();

    if (ec)
        return fail(ec, ErrorCode::NETWORK_RECEIVE_ERROR);

    http::response<http::string_body> res = res_parser_->get();

    // Write the message to standard out
    Header  response_headers;
    Cookies response_cookies;
    for (auto&& header : res.base()) {
        if (header.name() == http::field::set_cookie) {  // TODO: case insensitive
            response_cookies
                .parse_cookie_string(std::string(header.value()));
        } else {
            response_headers
                .insert_or_assign(
                    std::string(header.name_string()),
                    std::string(header.value()));
        }
    }

    if (res.result() == boost::beast::http::status::unauthorized) {
        if (generateAuthentication(res[boost::beast::http::field::www_authenticate])) {
            follow_next_redirect = true;
            return;
        }
    }

    // Gracefully close the stream
    if (is_tls_stream()) {
        auto& stream = tls_stream();
        stream.async_shutdown(
            std::bind(
                &Session::Impl::on_shutdown,
                shared_from_this(),
                std::placeholders::_1));
    } else {
        on_shutdown(ec);
    }

    if (res.result_int() >= 300 && res.result_int() <= 310 && response_headers.find("Location") != response_headers.end()) {
        SetUrl(response_headers["Location"]);
        if ((redirect_) && (number_of_redirects > 0)) {
            --number_of_redirects;
            follow_next_redirect = true;  // Follow the redirection
        }
    } else {
        on_response(xxhr::Response(
            res.result_int(),
            Error{},
            res.body(),
            response_headers,
            url_,
            response_cookies));
    }
}

void Session::Impl::on_shutdown(boost::system::error_code ec) {
    //if(ec == boost::asio::error::eof) {
    // Rationale:
    // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
    ec.assign(0, ec.category());
    //}
    if (ec)
        return fail(ec, ErrorCode::GENERIC_SSL_ERROR);

    // If we get here then the connection is closed gracefully
}

void Session::Impl::on_timeout(const boost::system::error_code& ec) {
    if (ec != boost::asio::error::operation_aborted) {
        ioc.stop();

        tcp::socket* socket;
        if (is_tls_stream()) {
            socket = &tls_stream().next_layer();
        } else {
            socket = &plain_stream();
        }

        boost::system::error_code ec_dontthrow;
        socket->cancel(ec_dontthrow);
        socket->close(ec_dontthrow);

        fail(ec, ErrorCode::TIMEDOUT);
    }
}
bool Session::Impl::generateAuthentication(boost::string_view authenticate) {
    // if (auth_.username.empty() || auth_.password.empty() || !req_[boost::beast::http::field::authorization].empty()) {
    //     return false;
    // }
    if (boost::ifind_first(authenticate, "digest")) {
        return generateDigestAuth(authenticate, boost::string_view());
    } else {
        return generateBasicAuthentication();
    }
}
bool Session::Impl::generateBasicAuthentication() {
    std::string credentials{auth_.username};
    credentials += ":" + auth_.password;
    std::stringstream ss;
    ss << "Basic " << util::encode64(credentials);
    req_.set(http::field::authorization, ss.str());

    return true;
}
bool Session::Impl::generateDigestAuth(boost::string_view authenticate, boost::string_view body) {
    
    if(!digest_.authenticate(authenticate)){
        return false; 
    }

    if (digest_.generateAuthorization(req_.target(), to_string(req_.method()), body)) {
        req_.set(boost::beast::http::field::authorization, digest_.authorization());
        return true;
    }
    return false;
}

void Session::Impl::SetUrl(const Url& url) {
    url_       = url;
    url_parts_ = util::parse_url(url);
}
void Session::Impl::SetParameters(Parameters&& parameters) {
    parameters_ = std::move(parameters);
}
void Session::Impl::SetParameters(const Parameters& parameters) {
    parameters_ = parameters;
}

void Session::Impl::SetHeader(const Header& header) {
    for (auto&& entry : header) {
        auto& h = entry.first;
        auto& v = entry.second;
        req_.set(boost::beast::http::string_to_field(h), v);
    }
}

void Session::Impl::SetTimeout(const Timeout& timeout) {
    timeout_ = timeout.ms;
}

void Session::Impl::SetAuth(const Authentication& auth) {
    namespace http = boost::beast::http;
    // std::stringstream ss;
    // ss << "Basic " << util::encode64(auth.GetAuthString());
    // req_.set(http::field::authorization, ss.str());
    auth_ = auth;
    generateBasicAuthentication();
}

void Session::Impl::SetDigest(Digest&& digest) 
{
    std::swap(digest_, digest);
}

void Session::Impl::SetMultipart(Multipart&& multipart) {
    constexpr auto boundary_str   = "---------------------------5602587876013262401422655391";
    constexpr auto boundary_delim = "--";

    req_.set(http::field::content_type, std::string("multipart/form-data; boundary=") + boundary_str);

    std::stringstream body;

    for (auto it = multipart.parts.begin(); it != multipart.parts.end(); ++it) {
        auto& part = *it;

        body << boundary_delim << boundary_str << CRLF;

        body << "Content-Disposition: form-data; name=\"" << part.name << "\"; "
             << "filename=\"" << part.value << "\"" << CRLF
             << "Content-Type: application/octet-stream"
             << CRLF
             << CRLF;

        if (part.is_file) {
            std::ifstream ifs(part.value, std::ios::in | std::ios::binary);
            ifs.exceptions(std::ios::badbit);

            ifs.seekg(0, ifs.end);
            auto file_size = ifs.tellg();
            ifs.seekg(0, ifs.beg);

            std::string file_content(file_size, std::string::value_type{});
            ifs.read(const_cast<char*>(file_content.data()), file_size);
            body.write(file_content.data(), file_content.size());
        } else if (part.is_buffer) {
            body.write(reinterpret_cast<const char*>(part.data), part.datalen);

        } else {
            body << part.value;
        }

        if (it != std::prev(multipart.parts.end())) {
            body << CRLF << boundary_delim << boundary_str << CRLF;
        } else {
            body << CRLF << boundary_delim << boundary_str << boundary_delim << CRLF;
        }
    }

    req_.body() = body.str();
    //std::cout << body.str() << std::endl;
}

void Session::Impl::SetMultipart(const Multipart& multipart) {
    SetMultipart(std::move(const_cast<Multipart&>(multipart)));
}

void Session::Impl::SetRedirect(const bool& redirect) {
    redirect_ = redirect;
}
void Session::Impl::SetMaxRedirects(const MaxRedirects& max_redirects) {
    number_of_redirects = max_redirects.number_of_redirects;
}

void Session::Impl::SetCookies(const Cookies& cookies, bool delete_them) {
    for (auto cookie : cookies.all()) {
        auto cookie_string =
            xxhr::util::urlEncode(cookie.first) + "=" +
            xxhr::util::urlEncode(cookie.second);

        req_.set(http::field::set_cookie, cookie_string);
    }
}

void Session::Impl::SetBody(const Body& body) {
    if (body.is_form_encoded) {
        req_.set(http::field::content_type, "application/x-www-form-urlencoded");
    }

    req_.body() = body.content;
}

void Session::Impl::do_one_request(http::verb method) {
    // Cleanup for subsequent calls
    follow_next_redirect = false;
    res_parser_          = std::make_shared<http::response_parser<http::string_body>>();

    // We need to download whatever fits in RAM
    res_parser_->body_limit(std::numeric_limits<std::uint64_t>::max());
    //TODO: change the limit for uploading too

    req_.method(method);

    req_.version(11);
    std::stringstream target;
    target << url_parts_.path;
    if (!url_parts_.parameters.empty() || !parameters_.content.empty()) {
        target << "?" << url_parts_.parameters << parameters_.content;
    }
    req_.target(target.str());

    
    std::stringstream host_port;
    host_port << url_parts_.host;
    if(url_parts_.port != "80" && url_parts_.port != "443"){
        host_port << ":" << url_parts_.port;
    }


    req_.set(http::field::host, host_port.str() ) ;
    req_.set(http::field::user_agent, "xxhr/v0.0.1");  //TODO: add a way to override from user and make a version macro
    req_.prepare_payload();                            // Compute Content-Length and related headers



    if(digest_.is_initialized() && digest_.generateAuthorization(req_.target(), to_string(req_.method()), boost::string_view())){
        req_.set(boost::beast::http::field::authorization, digest_.authorization());
    }

    
    //if(auto itr = digest_auth_cache.find())
    if (url_parts_.https()) {
        stream_.emplace<ssl::stream<tcp::socket>>(ioc, ctx);
    } else {
        stream_.emplace<tcp::socket>(ioc);
    }

    register_request();

    if (timeout_ != std::chrono::milliseconds(0)) {
        timeouter.expires_after(timeout_);
        timeouter.async_wait(std::bind(&Session::Impl::on_timeout, shared_from_this(), std::placeholders::_1));
    }
}

void Session::Impl::full_request(http::verb verb) {
    do {
        ioc.reset();
        do_one_request(verb);
        ioc.run();
    } while (follow_next_redirect);
}

void Session::Impl::DELETE_() { full_request(http::verb::delete_); }
void Session::Impl::GET() { full_request(http::verb::get); }
void Session::Impl::HEAD() { full_request(http::verb::head); }
void Session::Impl::OPTIONS() { full_request(http::verb::options); }
void Session::Impl::PATCH() { full_request(http::verb::patch); }
void Session::Impl::POST() { full_request(http::verb::post); }
void Session::Impl::PUT() { full_request(http::verb::put); }

// Forward to above pimpl


}  // namespace xxhr
