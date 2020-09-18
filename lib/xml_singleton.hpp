
#ifndef ASIO_SIRVICE_XML_HPP
#define ASIO_SIRVICE_XML_HPP
#include <vector>
#include <cstdint>

namespace asio_app{

struct xml_singleton{
public:
    static xml_singleton& instance();
    void sign(const std::vector<char>&, std::vector<char>&);
    bool verify(const std::vector<char>&);
private:
    bool init();
    xml_singleton();
    ~xml_singleton();
};

}

#endif //ASIO_SIRVICE_XML_HPP
