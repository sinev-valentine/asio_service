
#include "client.hpp"
#include <boost/asio/ip/address.hpp>
#include <iostream>
#include <boost/bind.hpp>
#include <boost/asio/read_until.hpp>
#include <fstream>
#include "srv.hpp"

namespace client {

using handler_t = std::function<void(std::string&, int code)>;


client::client(const std::string& ip, int port, std::vector<std::string>& head, std::string request_json, handler_t h,
               boost::asio::io_context& io_context, boost::asio::ssl::context& ssl_context):
            resolve_result(boost::asio::ip::tcp::resolver(io_context).resolve(ip, std::to_string(port))),
            started(true),
            headers(head),
            m_request_content(request_json),
            handler(h),
            m_response_content(""),
            http_code(static_cast<int>(srv::code_te::unknown)),
            ssl_stream(io_context, ssl_context)
{
}

bool client::verify_certificate(bool preverified,
                            boost::asio::ssl::verify_context& ctx)
{
    return true;
}

client::~client(){
    ssl_stream.lowest_layer().close();
}

void client::on_read_content(const boost::system::error_code& ec, std::size_t bytes_transferred){

    if (!ec){
        std::string content( (std::istreambuf_iterator<char>(&rx)), std::istreambuf_iterator<char>() );
        m_response_content += content.substr(0, bytes_transferred);
        handler(m_response_content, http_code);
        close();
    }
    else if (ec != boost::asio::error::operation_aborted){
        close();
    }

}
void client::on_read(const boost::system::error_code& ec, std::size_t bytes_transferred){
    if (!ec){
        std::istream strm(&rx);
        uint32_t content_length=0;
        bool found = false;
        std::string value, http_status;
        strm >> http_status >> http_status;
        try{
            http_code = std::stoi(http_status);
        }
        catch(std::exception & exc){
            http_code = static_cast<int>(srv::code_te::unknown);
        }

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
            m_response_content = fragment.substr(pos+4);
        }

        if (m_response_content.length() < content_length){
            boost::asio::async_read(ssl_stream, rx, boost::asio::transfer_exactly(content_length-m_response_content.length()),
                                          boost::bind(&client::on_read_content, shared_from_this(), _1, _2));
        }
        else{
            handler(m_response_content, http_code);
            close();
        }

    }
    else if (ec != boost::asio::error::operation_aborted){
        close();
    }
}

void client::do_read(){

    boost::asio::async_read_until(ssl_stream, rx, CRLF,
            boost::bind(&client::on_read, shared_from_this(), _1, _2));
}

void client::do_write(){
    if(!started) return;
    for (auto& a : headers){
        tx += a + "\r\n";
    }
    if(m_request_content.size()){
        tx += "Content-Length: "+ std::to_string(m_request_content.size())+"\r\n";
    }
    tx += "\r\n"+m_request_content;

    boost::asio::async_write(ssl_stream, boost::asio::buffer(tx),
                            boost::bind(&client::on_write, shared_from_this(), _1, _2));
}

void client::on_write(const boost::system::error_code& error, size_t bytes){
    do_read();
}

void client::do_connect(){
    ssl_stream.set_verify_mode(boost::asio::ssl::verify_peer);  // no CA
    ssl_stream.set_verify_callback( boost::bind(&client::verify_certificate, shared_from_this(), _1, _2));

    boost::asio::async_connect(ssl_stream.lowest_layer(), resolve_result,
            boost::bind(&client::on_connect, shared_from_this(), _1, _2));
}

void client::on_connect(const boost::system::error_code& error, const tcp::endpoint& ep){
    if (!error){
        do_handshake();
    } else{
        std::cout << "https connection failed" << std::endl;
        close();
    }
}

void client::do_handshake(){
    ssl_stream.async_handshake(boost::asio::ssl::stream_base::client, boost::bind(&client::on_handshake,
            shared_from_this(), _1));
}

void client::on_handshake(const boost::system::error_code& error){
    if (!error)
    {
        do_write();
    }
    else
    {
        std::cout << "Handshake failed: " << error.message() << "\n";
        close();
    }
}

boost::shared_ptr<client> client::instance(const std::string& ip, int port, std::vector<std::string>& head,
        std::string request_json, handler_t h){

    boost::asio::ssl::context ssl_context(boost::asio::ssl::context::tlsv13);
    boost::asio::io_context io_context;
    std::ifstream file(CLIENT_HTTPS_CERT);
    FC_LIGHT_ASSERT(file, "error open cert file " CLIENT_HTTPS_CERT);
    ssl_context.load_verify_file(CLIENT_HTTPS_CERT);

    auto instance = boost::shared_ptr<client>(new client(ip, port, head, request_json, h, io_context, ssl_context));
    instance->do_connect();
    io_context.run();
    return instance;
}

void client::close(){
    if(!started) return;
    started = false;
    ssl_stream.lowest_layer().close();
}

}

