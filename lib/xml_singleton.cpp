
#include "xml_singleton.hpp"
#include <libxml/tree.h>
#include <libxml/c14n.h>

#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>
#include <fc_light/exception/exception.hpp>
#include "global.hpp"
#include "sha_wrapper.hpp"
#include <fc_light/crypto/base64.hpp>

#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include <iostream>

#include <fstream>

namespace asio_app{

xml_singleton::xml_singleton(){}

bool xml_singleton::init(){
    xmlInitParser();
    auto res = xmlSecInit();
    FC_LIGHT_ASSERT(res == 0, "xmlsec initialization failed");

    res = xmlSecCryptoDLLoadLibrary(NULL);
    FC_LIGHT_ASSERT(res == 0, "unable to load default xmlsec-crypto library");
}

xml_singleton::~xml_singleton(){
    xmlSecShutdown();
    xmlCleanupParser();
};

xml_singleton& xml_singleton::instance() {
    static xml_singleton instance;
    static auto is_init = instance.init();
    return instance;
}

auto node = [](xmlNodePtr  node, std::string name){
    while(node != NULL){
        if ((!xmlStrcmp(node->name, (const xmlChar *)name.c_str()))) {
            return node;
        }
        node = node->next;
    }
    return node;
};

auto c14n_sha1 = [](xmlDocPtr main_doc, bool all_doc ){
    xmlChar * bin = nullptr;
    xmlChar * c14n_obj = nullptr;
    xmlDocPtr c14n_doc = nullptr;
    int bin_size;

    auto free_docs = [&](){
        if (c14n_obj != nullptr) {xmlFree(c14n_obj); c14n_obj= nullptr;}
        if (c14n_doc != nullptr) {xmlFreeDoc(c14n_doc); c14n_doc= nullptr;}
        if (bin != nullptr) {xmlFree(bin); bin = nullptr;};
    };

    try{
        xmlC14NDocDumpMemory(main_doc, nullptr, xmlC14NMode::XML_C14N_1_0, nullptr, 1, &c14n_obj);
        c14n_doc = xmlParseDoc(c14n_obj);
        xmlDocDumpMemory(c14n_doc, &bin, &bin_size);

        std::string str((char*)bin, bin_size);
        size_t beg, end;
        if (all_doc){
            beg = 0;
            end = str.size();
        }
        else{
            beg = str.find("<SignedInfo>");
            if (beg == std::string::npos)  throw std::runtime_error("<SignedInfo> error");
            end = str.find("</SignedInfo>");
            if (end == std::string::npos)  throw std::runtime_error("</SignedInfo> error");
            end +=  std::string ("</SignedInfo>").size();
        }
        auto sha1 = sha1_160(const_cast<char*>(str.data()+beg ), end-beg);
        free_docs();
        return sha1;
    }
    catch(std::exception& e){
        free_docs();
        throw std::runtime_error("c14n_sha1 error");
    }
};


void xml_singleton::sign(const std::vector<char>& src, std::vector<char>& dst ) {
    xmlDocPtr doc = nullptr;
    xmlChar * xml = nullptr;

    auto free_docs = [&](){
        if (doc != nullptr) {xmlFreeDoc(doc); doc = nullptr;};
        if (xml != nullptr) {xmlFree(xml); xml = nullptr;};
    };

    try{
        doc = xmlParseMemory(src.data(), src.size());
        FC_LIGHT_ASSERT(doc != nullptr && xmlDocGetRootElement(doc) != nullptr, "xmlParseMemory error");
        // sha1(c14n(src))
        auto sha1 = c14n_sha1(doc, true);
        auto base64 = fc_light::base64_encode(sha1.data(), sha1.size());

        /* create signature template for RSA-SHA1 enveloped signature */
        auto signNode = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId,
                                             xmlSecTransformRsaSha1Id, nullptr);
        FC_LIGHT_ASSERT(signNode != nullptr, "xmlSecTmplSignatureCreate error");
        /* add <dsig:Signature/> node to the doc */
        xmlAddChild(xmlDocGetRootElement(doc), signNode);
        /* add reference */
        auto refNode = xmlSecTmplSignatureAddReference(signNode, xmlSecTransformSha1Id,
                                                  nullptr, nullptr, nullptr);
        FC_LIGHT_ASSERT(refNode != nullptr, "xmlSecTmplSignatureAddReference error");
        /* add enveloped transform */
        FC_LIGHT_ASSERT(xmlSecTmplReferenceAddTransform(refNode, xmlSecTransformEnvelopedId) != nullptr,
                "xmlSecTmplReferenceAddTransform error");
        /* add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to put key name in the signed document */
        auto keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, nullptr);
        FC_LIGHT_ASSERT(signNode != nullptr, "xmlSecTmplSignatureEnsureKeyInfo error");
        FC_LIGHT_ASSERT(xmlSecTmplKeyInfoAddKeyName(keyInfoNode, nullptr) != nullptr, "xmlSecTmplKeyInfoAddKeyName error");

        auto cur = xmlDocGetRootElement(doc)->xmlChildrenNode;
        cur = node (cur, "Signature");
        FC_LIGHT_ASSERT(cur != nullptr, "xmlDocGetRootElement error");

        auto sign_val_node  = node (cur->xmlChildrenNode, "SignatureValue");
        FC_LIGHT_ASSERT(sign_val_node != nullptr, "get SignatureValue error");

        auto key_node  = node (cur->xmlChildrenNode, "KeyInfo");
        FC_LIGHT_ASSERT(key_node != nullptr, "get KeyInfo error");
        key_node  = node (key_node->xmlChildrenNode, "KeyName");
        FC_LIGHT_ASSERT(key_node != nullptr, "get KeyName error");
        xmlNodeSetContent(key_node,  (const xmlChar *) KEY_FILE);

        cur = node (cur->xmlChildrenNode, "SignedInfo");
        FC_LIGHT_ASSERT(cur != nullptr, "get SignedInfo error");
        auto si_node = cur;
        cur = node (cur->xmlChildrenNode, "Reference");
        FC_LIGHT_ASSERT(cur != nullptr, "get Reference error");
        cur = node (cur->xmlChildrenNode, "DigestValue");
        FC_LIGHT_ASSERT(cur != nullptr, "get DigestValue error");
        // set sha1(c14n(src)) to DigestValue
        xmlNodeSetContent(cur,  (const xmlChar *) base64.c_str());

        // calc sign
        std::ifstream src(KEY_FILE, std::ios::binary);
        FC_LIGHT_ASSERT(src.is_open(), "error open file with private key " KEY_FILE);
        std::vector<char> pk_key(std::istreambuf_iterator<char>(src), {});

        std::shared_ptr<BIO> priv_bio(BIO_new_mem_buf(pk_key.data(), pk_key.size()), [](auto a){BIO_free_all(a);});
        FC_LIGHT_ASSERT(priv_bio.get() != nullptr, "BIO_new_mem_buf error");

        std::shared_ptr<RSA> private_key(PEM_read_bio_RSAPrivateKey(priv_bio.get(), NULL, NULL, NULL),
                [](auto a){RSA_free(a);});
        FC_LIGHT_ASSERT(private_key.get() != nullptr, "PEM_read_bio_RSAPrivateKey error");

        unsigned int slen;
        std::vector<uint8_t> signature(RSA_size(private_key.get()));

        // sha1(c14n(SignedInfo))
        sha1 = c14n_sha1(doc, false);

        auto res = RSA_sign(NID_sha1, reinterpret_cast<uint8_t*>(sha1.data()), sha1.size(),
                    signature.data(), &slen, private_key.get());
        FC_LIGHT_ASSERT(res == 1, "RSA_sign error");

        //  signature size corresponds to the RSA key size.
        if (slen != signature.size()) abort;

        base64 = fc_light::base64_encode(signature.data(), slen);

        // set rsa(sha1(c14n(SignedInfo))) to SignatureValue
        xmlNodeSetContent(sign_val_node,  (const xmlChar *) base64.c_str());

        int len;
        xmlDocDumpMemory(doc, &xml, &len);
        std::vector<char>vec (xml, xml+len);
        dst = std::move(vec);

        free_docs();
        return;
    }
    catch(fc_light::exception& e){
        free_docs();
        FC_LIGHT_THROW_EXCEPTION(fc_light::internal_error_exception, e.to_string().c_str());
    }
    catch(std::exception& e){
        free_docs();
        FC_LIGHT_THROW_EXCEPTION(fc_light::internal_error_exception, e.what());
    }
}

bool xml_singleton::verify(const std::vector<char>& src){
    xmlDocPtr doc = nullptr;
    xmlChar * xml = nullptr;
    int len;

    auto free_docs = [&](){
        if (doc != nullptr) {xmlFreeDoc(doc); doc = nullptr;};
        if (xml != nullptr) {xmlFree(xml); xml = nullptr;};
    };

    try{
        doc = xmlParseMemory(src.data(), src.size());
        FC_LIGHT_ASSERT(doc != nullptr && xmlDocGetRootElement(doc) != nullptr);


        auto cur = xmlDocGetRootElement(doc)->xmlChildrenNode;
        cur = node (cur, "Signature");
        FC_LIGHT_ASSERT(cur != nullptr);
        // find SignatureValue node
        auto sign_val_node  = node (cur->xmlChildrenNode, "SignatureValue");
        FC_LIGHT_ASSERT(sign_val_node != nullptr);
        // read signature
        const char* val = reinterpret_cast<const char*>(sign_val_node->children->content);
        FC_LIGHT_ASSERT(val != nullptr);
        std::string sign_base64 (val);
        std::string signature= fc_light::base64_decode(sign_base64);

        // sha1(c14n(SignedInfo))
        auto sha1 = c14n_sha1(doc, false);
        // verify sign
        std::ifstream src(PUB_KEY_FILE, std::ios::binary);
        FC_LIGHT_ASSERT(src.is_open());
        std::vector<char> pub_key(std::istreambuf_iterator<char>(src), {});

        std::shared_ptr<BIO> pub_bio(BIO_new_mem_buf(pub_key.data(), pub_key.size()), [](auto a){BIO_free_all(a);});
        FC_LIGHT_ASSERT(pub_bio.get() != nullptr);

        std::shared_ptr<RSA> rsa_pub_key(PEM_read_bio_RSA_PUBKEY(pub_bio.get(), NULL, NULL, NULL),
                                         [](auto a){RSA_free(a);});
        FC_LIGHT_ASSERT(rsa_pub_key.get() != nullptr);

        auto res = RSA_verify(NID_sha1, reinterpret_cast<uint8_t*>(sha1.data()), sha1.size(),
                              reinterpret_cast<const uint8_t *>(signature.data()),
                              signature.size(), rsa_pub_key.get());

        free_docs();
        return res;
    }
    catch(fc_light::exception& e){
        free_docs();
        FC_LIGHT_THROW_EXCEPTION(fc_light::internal_error_exception, "verify error");
    }
    catch(std::exception& e){
        free_docs();
        FC_LIGHT_THROW_EXCEPTION(fc_light::internal_error_exception, "verify error");
    }

    return true;
};


}
