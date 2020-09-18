
#ifndef ASIO_SERVICE_SEND_HPP
#define ASIO_SERVICE_SEND_HPP

struct request_t{
    char * cmd;
    char * params;
};

struct response_t{
    bool res;
    char * params;
};

#ifdef __cplusplus
extern "C" {
#endif

response_t* send_message(request_t*);

#ifdef __cplusplus
}
#endif

#endif //ASIO_SERVICE_SEND_HPP
