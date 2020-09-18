
#ifndef ASIO_SIRVICE_TRACE_HPP
#define ASIO_SIRVICE_TRACE_HPP

#include <fc_light/reflect/reflect.hpp>
#include <fc_light/reflect/variant.hpp>
#include <fc_light/variant.hpp>
#include <fc_light/io/json.hpp>
#include <fc_light/exception/exception.hpp>

namespace asio_app{

struct err_msg {
    err_msg(int id_,
            fc_light::exception_code_te err_code,
            const std::string &msg_ = "",
            const fc_light::variant &trace_ = fc_light::variant())
            : id(id_),
            error(err_code, msg_, trace_) {}

    struct error_t {
        error_t(fc_light::exception_code_te code_,
                const std::string &message_,
                const fc_light::variant &trace_):
                code(static_cast<int>(code_)),
                name(code_),
                message(message_),
                trace(trace_) {}

        error_t() : code(0) {}

        int code;
        fc_light::exception_code_te name;
        std::string message;
        fc_light::variant trace;
    } error;

    int id;
};


auto exc_handler_variant = [](const fc_light::exception &exc) {
    auto err_logs = exc.get_log();
    std::vector<fc_light::log_context> log_contexts(err_logs.size());

    std::transform(err_logs.begin(), err_logs.end(), log_contexts.begin(), [](const auto &val) {
        return val.get_context();
    });
    return fc_light::variant(err_msg(0, static_cast<fc_light::exception_code_te>(exc.code()),
            exc.to_string().c_str(), fc_light::variant(log_contexts)));
};

auto exc_handler = [](const fc_light::exception &exc) {
    return fc_light::json::to_pretty_string(exc_handler_variant(exc));
};

}


FC_LIGHT_REFLECT(asio_app::err_msg::error_t, (code)(name)(message)(trace))
FC_LIGHT_REFLECT(asio_app::err_msg, (id)(error))

#endif //ASIO_SIRVICE_TRACE_HPP
