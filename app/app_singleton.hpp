#ifndef ASIO_APP_SINGLETON_HPP
#define ASIO_APP_SINGLETON_HPP

#include "srv.hpp"

namespace asio_app{


struct app_singleton {
    static app_singleton& instance();
    std::pair<std::string, srv::code_te > operator()(const std::string&, const std::string&);
private:
    app_singleton();
    ~app_singleton();
};

}



#endif //ASIO_APP_SINGLETON_HPP
