#ifndef TLS_PEER_LIST_HPP
#define TLS_PEER_LIST_HPP

#include <boost/core/noncopyable.hpp>
#include <set>

namespace srv {

template<typename T>
class tls_peer_list : public boost::noncopyable
{
public:
  tls_peer_list(){};
  ~tls_peer_list(){};

  void start(T c){ peers.insert(c); c->start(); }
  void stop(T c){peers.erase(c); c->stop();}
  void stop_all(){for (auto c: peers) c->stop(); peers.clear();};

private:
  std::set<T> peers;
};

}

#endif // TLS_PEER_LIST_HPP
