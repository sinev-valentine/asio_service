#ifndef TLS_SRV_HPP
#define TLS_SRV_HPP

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "tls_peer.hpp"
#include "tls_peer_list.hpp"
#include "global.hpp"

namespace srv {

struct server : public boost::noncopyable
{
    explicit server(const std::string& address, const std::string& port, handler_t handler);

    void run();

protected:
    void do_accept();

    void do_await_stop();

    void on_await_stop(const boost::system::error_code&, int);

    boost::asio::io_context io_context_;

    boost::asio::signal_set signals_;

    boost::asio::ip::tcp::acceptor acceptor_;

    tls_peer_list<tls_peer::tls_peer_ptr> tls_peer_list_;

    handler_t handler;
    boost::asio::ssl::context ssl_context;

};


}

#endif //TLS_SRV
