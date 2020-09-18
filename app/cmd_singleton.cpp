#include "cmd_singleton.hpp"
#include <openssl/rsa.h>

namespace asio_app{

cmd_singleton::~cmd_singleton(){}

const cmd_singleton& cmd_singleton::instance(){
    static const cmd_singleton instance;
    return instance;
}

cmd_singleton::cmd_singleton()
{
    m_handler_list.reserve(32);
    hana::for_each(cmd_static_list, [&](auto val) {
        using value_type = decltype(val);
        constexpr auto const_val = static_cast<cmd_list_te>(value_type::value);
        m_handler_list.push_back(handler_ptr(new cmd_handler<const_val>));
    });
}

const cmd_singleton::handler_ptr cmd_singleton::operator[](cmd_list_te cmd) const
{
    size_t ind = static_cast<size_t>(cmd);
    if (ind >= m_handler_list.size())
        return m_handler_list[0];
    return m_handler_list[ind];
}


}
