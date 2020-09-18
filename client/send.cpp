
#include <iostream>
#include "client.hpp"
#include "srv.hpp"
#include "cmd_singleton.hpp"
#include <fstream>

#include <fc_light/exception/exception.hpp>
#include "sha_wrapper.hpp"
#include <fc_light/crypto/base64.hpp>
#include "xml_singleton.hpp"
#include "send.hpp"

response_t result;
std::string response_content;

response_t* send_message(request_t* request) {
    try{
        std::string ip = "0.0.0.0";
        uint32_t port = 1024;

        result.params = const_cast<char*>("");

        auto http_handler = [](const std::string json, int http_code) {
            if (http_code != static_cast<int>(srv::code_te::ok)) {
                response_content.assign("response error:  " +
                            fc_light::variant(static_cast<srv::code_te >(http_code)).as_string()+ " " + json);
                result.params = const_cast<char*>(response_content.c_str());
                result.res = false;
                return;
            }
            asio_app::cmd_handler<asio_app::cmd_list_te::xml_sign>::content_t response;
            try{
                 response = fc_light::json::from_string(json).as<asio_app::cmd_handler<asio_app::cmd_list_te::xml_sign>::content_t>();
            }
            catch(fc_light::bad_cast_exception& ext){
                response_content.assign("bad cast response: "+ json);
                result.params = const_cast<char*>(response_content.c_str());
                result.res = false;
                return;
            }
            // if OK, then verify
            auto& xml = asio_app::xml_singleton::instance();
            result.res = xml.verify(response.raw_signed_xml);
            response_content.assign(response.raw_signed_xml.data(), response.raw_signed_xml.size());
            result.params = const_cast<char*>(response_content.c_str());
        };

        std::string xml(request->params);
        std::vector<char> raw_xml(xml.begin(), xml.end());

        asio_app::params_t params;
        params.raw_xml = std::move(raw_xml);
        auto body = fc_light::json::to_string(fc_light::variant(params));
        auto uri = std::string (request->cmd);

        std::vector<std::string> headers = { "POST "+ uri,"Host: "+ip+":"+std::to_string(port)};
        client::handler_t handler = std::bind(http_handler, std::placeholders::_1, std::placeholders::_2 );
        client::client::instance(ip, port, headers, body, handler);

        return &result;

    }catch(fc_light::exception& exc){
        auto error_msg = asio_app::exc_handler(exc);
        result.res = false;
        result.params = const_cast<char*>(error_msg.c_str());
    }
    catch( const std::exception& e ) {
        auto error_msg = fc_light::json::to_pretty_string(
                fc_light::variant(asio_app::err_msg(0, fc_light::std_exception_code,  std::string(e.what()))));
        result.res = false;
        result.params = const_cast<char*>(error_msg.c_str());
    }
    return &result;
}
