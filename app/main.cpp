#include <iostream>
#include "tls_srv.hpp"
#include <functional>
#include "app_singleton.hpp"
#include "trace.hpp"

int main(int argc, char* argv[]) {
    std::string ip = "0.0.0.0";
    uint32_t port = 1024;

    try{
        auto& app = asio_app::app_singleton::instance();
        srv::handler_t handler = std::bind(&asio_app::app_singleton::operator(),
                                                    &app,
                                                    std::placeholders::_1,
                                                    std::placeholders::_2);
        auto port_str = std::to_string(port);
        auto server = std::make_shared<srv::server>(ip, port_str, handler);
        server->run();

    }catch(fc_light::exception& exc){
        auto error_msg = asio_app::exc_handler(exc);
        std::cout<< error_msg << std::endl;
    }
    catch( const std::exception& e ) {
        auto error_msg = fc_light::json::to_pretty_string(
                fc_light::variant(asio_app::err_msg(0, fc_light::std_exception_code,  std::string(e.what()))));
        std::cout<< error_msg << std::endl;
    }
    catch( ... ) {
        auto error_msg = fc_light::json::to_pretty_string(
                fc_light::variant(asio_app::err_msg(0, fc_light::unhandled_exception_code)));
        std::cout<< error_msg << std::endl;
    }
    return 0;

}