#ifndef ASIO_CMD_SINGLETON_HPP
#define ASIO_CMD_SINGLETON_HPP

#include <iostream>
#include <boost/hana.hpp>
#include <boost/hana/range.hpp>
#include <boost/hana/for_each.hpp>
#include <boost/hana/size.hpp>
#include "trace.hpp"
#include "srv.hpp"
#include "xml_singleton.hpp"

namespace asio_app{

namespace hana=boost::hana;

enum struct cmd_list_te{
    unknown=0,
    xml_sign,
    last
};

struct response_t {
    fc_light::variant content;
    srv::code_te http;
};

struct params_t {
    std::vector<char> raw_xml;
};

// base abstraction class of api-commands handlerls
struct cmd_handler_base {
    cmd_handler_base(){};
    virtual ~cmd_handler_base(){};
    virtual fc_light::variant operator()(const fc_light::variant&) const = 0;
};

// handler for not implemented api-commands
template<cmd_list_te T>
struct cmd_handler : cmd_handler_base {
    virtual ~cmd_handler(){};
    virtual fc_light::variant operator()(const fc_light::variant&) const override{
        response_t response;
        response.http = srv::code_te::server_error;
        response.content = fc_light::variant("command is not implemented");
        return fc_light::variant(response);
    };
};

//handler of api-command sign
template<>
struct cmd_handler<cmd_list_te::xml_sign> : cmd_handler_base {
    struct content_t{
        std::vector<char> raw_signed_xml;
    };
    virtual ~cmd_handler(){};
    virtual fc_light::variant operator()(const fc_light::variant& variant) const override{
        response_t response;
        params_t params;
        content_t content;
        try{
            params =variant.as<params_t>();
            auto& xml = xml_singleton::instance();
            xml.sign(params.raw_xml, content.raw_signed_xml);
            response.content = fc_light::variant(content);
            response.http = srv::code_te::ok;
        }
        catch(fc_light::exception& exc)
        {
            // send desc of the exception
            auto msg = asio_app::exc_handler(exc);
            std::cout << msg << std::endl;

            response.content = asio_app::exc_handler_variant(exc);
            response.http = srv::code_te::server_error;
        }
        return fc_light::variant(response);
    };
};

struct cmd_singleton {
    using handler_ptr = std::shared_ptr<cmd_handler_base>;
    static const cmd_singleton& instance();
    const handler_ptr operator[](cmd_list_te) const;
private:
    cmd_singleton();
    ~cmd_singleton();
    std::vector<handler_ptr> m_handler_list;
};

constexpr auto cmd_static_list =
        hana::make_range(
                hana::int_c<static_cast<int>(cmd_list_te::unknown)>,
                hana::int_c<static_cast<int>(cmd_list_te::last)>);
}


FC_LIGHT_REFLECT(asio_app::response_t, (content)(http))
FC_LIGHT_REFLECT_ENUM(asio_app::cmd_list_te,(unknown)(xml_sign)(last))
FC_LIGHT_REFLECT(asio_app::params_t, (raw_xml))
FC_LIGHT_REFLECT(asio_app::cmd_handler<asio_app::cmd_list_te::xml_sign>::content_t, (raw_signed_xml))

#endif //ASIO_CMD_SINGLETON_HPP
