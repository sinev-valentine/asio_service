
#include "app_singleton.hpp"
#include "cmd_singleton.hpp"

namespace asio_app{

app_singleton::app_singleton(){}
app_singleton::~app_singleton(){}

app_singleton& app_singleton::instance(){
    static app_singleton instance;
    return instance;
}

std::pair<std::string, srv::code_te > app_singleton::operator()(const std::string& uri, const std::string& json)
{
    auto cmd = asio_app::cmd_list_te::unknown;
    try{
        auto variant = fc_light::variant(uri);
        cmd = variant.as<asio_app::cmd_list_te>();
    }
    catch(fc_light::bad_cast_exception& ext){
        fc_light::rpc_command_parse_exception er_(ext.get_log());
        er_.append_log(FC_LIGHT_LOG_MESSAGE(error, "unknown command"));
        auto response = std::make_pair("", srv::code_te::invalid_cmd);
        return response;
    }
    catch(fc_light::exception& exc)
    {
        auto response = std::make_pair("", srv::code_te::invalid_cmd);
        return response;
    }

    fc_light::variant params;
    if (!json.empty()){
        try{
            params = fc_light::json::from_string(json);
        }
        catch (fc_light::parse_error_exception& exc)
        {
            fc_light::rpc_command_parse_exception er_(exc.get_log());
            er_.append_log(FC_LIGHT_LOG_MESSAGE(error, "cannot convert json to variant"));
            auto response = std::make_pair("", srv::code_te::invalid_json);
            return response;
        }
        catch(fc_light::exception& exc)
        {
            auto response = std::make_pair("", srv::code_te::invalid_json);
            return response;
        }
    }

    try{
        auto& functor_map = cmd_singleton::instance();
        auto func = functor_map[cmd];
        auto variant =  (*func)(params);
        auto result = variant.as<asio_app::response_t>();
        auto response = std::make_pair(fc_light::json::to_pretty_string(result.content), result.http);
        return response;
    }
    catch(fc_light::exception& exc)
    {
        auto response = std::make_pair("", srv::code_te::server_error);
        return response;
    }
    catch( const std::exception& e ) {
        auto response = std::make_pair("", srv::code_te::server_error);
        return response;
    }
    catch( ... ) {
        auto response = std::make_pair("",srv::code_te::server_error);
        return response;
    }
}


}