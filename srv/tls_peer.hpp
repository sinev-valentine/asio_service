
#ifndef TLS_PEER_HPP
#define TLS_PEER_HPP

#include <array>
#include <memory>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <memory>
#include "srv.hpp"
#include "tls_peer_list.hpp"

#define CRLF "\r\n\r\n"

namespace srv {

typedef boost::asio::ip::tcp::socket tcp_socket;
typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;

using handler_t = std::function<std::pair<std::string, srv::code_te>(const std::string &, const std::string &)>;


struct tls_peer: public  std::enable_shared_from_this<tls_peer>, boost::noncopyable
{
public:

    typedef std::shared_ptr<tls_peer> tls_peer_ptr;

    tls_peer(tcp_socket socket,
               tls_peer_list<tls_peer_ptr>& manager,
               handler_t& func,
               boost::asio::ssl::context&  ssl_context)
            : socket_(std::move(socket), ssl_context ),
              tls_peer_list_(manager),
              handler(func),
              stopped_(false),
              json(""),
              uri("")   {}
    ~tls_peer(){ socket_close();}

    void on_handshake(const boost::system::error_code& error) {
        if (!error) {
            do_read();
        } else {
            socket_close();
        }
    }

    void start(){
        do_handshake();
    }

    void stop(){
        socket_close();
        stopped_ = true;
    }

protected:

    void socket_close() {
        socket_.lowest_layer().close();
    }

    void socket_shutdown() {
        boost::system::error_code ignored_ec;
        socket_.lowest_layer().shutdown(tcp_socket::shutdown_both, ignored_ec);
    }

    void do_handshake() {
        auto self(this->shared_from_this());
        socket_.async_handshake(boost::asio::ssl::stream_base::server,
                                boost::bind(&tls_peer::on_handshake,
                                            this->shared_from_this(), _1)
        );
    }

    void on_read_content(const boost::system::error_code& ec, std::size_t bytes_transferred){

        if (!ec){
            std::string content( (std::istreambuf_iterator<char>(&rx)), std::istreambuf_iterator<char>() );
            json += content.substr(0, bytes_transferred);
            response = handler(uri, json);
            do_write();
        }
        else if (ec != boost::asio::error::operation_aborted){
            tls_peer_list_.stop(this->shared_from_this());
        }
    }

    void on_read(const boost::system::error_code& ec, std::size_t bytes_transferred){
        if (!ec)
        {
            std::istream strm(&rx);
            uint32_t content_length=0;
            bool found = false;
            std::string value, method;
            strm >> method >>uri;

            while(!strm.eof()){
                if (found){
                    strm >> content_length;
                    break;
                }
                strm >> value;
                std::transform(value.begin(), value.end(), value.begin(), ::tolower);
                if (value=="content-length:"){ found = true;}
            }

            std::string fragment( (std::istreambuf_iterator<char>(&rx)), std::istreambuf_iterator<char>() );
            auto pos = fragment.find(CRLF);
            if (pos != std::string::npos){
                json = fragment.substr(pos+4);
            }

            if (json.length() < content_length){
                boost::asio::async_read(socket_, rx, boost::asio::transfer_exactly(content_length-json.length()),
                                        boost::bind(&tls_peer::on_read_content, this->shared_from_this(),
                                                _1, _2));
            }
            else{
                response = handler(uri, json);
                do_write();
            }
        }
        else if (ec != boost::asio::error::operation_aborted)
        {
            tls_peer_list_.stop(this->shared_from_this());
        }
    }


    void on_write(const boost::system::error_code& ec,  unsigned long bytes_transferred){
        if (!ec)  {
            boost::system::error_code ignored_ec;
            socket_shutdown();
        }

        if (ec != boost::asio::error::operation_aborted) {
            tls_peer_list_.stop(this->shared_from_this());
        }
    }

    void do_read() {
        boost::asio::async_read_until(socket_, rx, CRLF,
                                      boost::bind(&tls_peer::on_read, this->shared_from_this(), _1, _2));
    }

    void do_write() {
        std::string tx, http_status;
        tx = "HTTP/1.0 "+std::to_string(static_cast<int>(response.second))+" "+fc_light::variant(response.second).as_string()+
             "\r\n";
        tx += response.first.length()?"Content-Length: "+std::to_string(response.first.length())+CRLF+response.first:"\r\n";
        boost::asio::async_write(socket_, boost::asio::buffer(tx),
                                 boost::bind(&tls_peer::on_write, this->shared_from_this(), _1, _2));
    }

    ssl_socket socket_;

    tls_peer_list<tls_peer_ptr>& tls_peer_list_;

    boost::asio::streambuf rx;

    bool stopped_;

    std::string json, uri;

    handler_t handler;

    std::pair<std::string, srv::code_te> response;
};


}

#endif // TLS_PEER_HPP

