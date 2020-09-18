
#ifndef SRV_HPP
#define SRV_HPP

#include <fc_light/reflect/reflect.hpp>
#include <fc_light/reflect/variant.hpp>
#include <fc_light/variant.hpp>
#include <fc_light/io/json.hpp>
#include <fc_light/exception/exception.hpp>

namespace srv {
enum struct code_te {
    unknown = 0,
    ok = 200,
    invalid_json = 400,
    invalid_cmd = 404,
    server_error = 500
};
}

FC_LIGHT_REFLECT_ENUM(srv::code_te,
                      (unknown)
                      (ok)
                      (invalid_json)
                      (invalid_cmd)
                      (server_error)
)

#endif //SRV_HPP
