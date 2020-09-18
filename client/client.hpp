#ifndef CLIENT_HPP
#define CLIENT_HPP
#include <boost/core/noncopyable.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "global.hpp"

#define CRLF "\r\n\r\n"

namespace client {
    using boost::asio::ip::tcp;

    using handler_t = std::function<void(std::string&, int code)>;

class client : public boost::enable_shared_from_this<client>, boost::noncopyable{
    client(const std::string& ip, int port, std::vector<std::string>& head, std::string json, handler_t h,
           boost::asio::io_context&, boost::asio::ssl::context& );
    void do_connect();
    void do_read();
    void do_write();
    void close();
    void on_connect(const boost::system::error_code&, const tcp::endpoint& );
    void on_write(const boost::system::error_code&, size_t);
    void on_read(const boost::system::error_code&, size_t);
    void on_read_content(const boost::system::error_code&, size_t);
    void do_handshake();
    void on_handshake(const boost::system::error_code&);
    bool verify_certificate(bool preverified, boost::asio::ssl::verify_context& ctx);

    handler_t handler;
public:
    static boost::shared_ptr<client> instance(const std::string& ip, int port, std::vector<std::string>& head,
            std::string json, handler_t h);
    ~client();

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_stream;
    boost::asio::ip::tcp::resolver::results_type resolve_result;

    boost::asio::streambuf rx;
    std::string tx;
    bool started;
    std::vector<std::string> headers;
    std::string m_request_content;
    std::string m_response_content;
    int http_code;
};

}
#endif //CLIENT_HPP
