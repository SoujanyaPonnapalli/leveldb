#include <openssl/sha.h>
#include <sstream>
#include <string>
#include <iostream>
#include <string.h>

namespace leveldb {

  // TODO[Soujanya] : Add Keccak256 hash functions too
  class cryptoHash {
   
   public:
    const std::string sha256(const char* arg) {
      unsigned char digest[SHA256_DIGEST_LENGTH];
      SHA256_CTX ctx;
      SHA256_Init(&ctx);
      SHA256_Update(&ctx, arg, strlen(arg));
      SHA256_Final(digest, &ctx);

      char mdString[SHA256_DIGEST_LENGTH*2+1];
      for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

      const std::string ret(mdString);
      return ret;
    }

    const std::string getHash(const long unsigned key) {
      if (key == 0) {
        return "";
      }

      std::string arg = std::to_string(key);
      return sha256(arg.c_str());
    }

    const std::string getHash(const char* key) {
      if (key == NULL) {
        return "";
      }
      return sha256(key);
    }

  };

} //namespace leveldb
