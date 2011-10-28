#ifndef __LIBOAUTHCPP_LIBOAUTHCPP_H__
#define __LIBOAUTHCPP_LIBOAUTHCPP_H__

#include <string>
#include <list>
#include <map>

namespace OAuth {

namespace Http {
typedef enum _RequestType
{
    Invalid = 0,
    Get,
    Post,
    Delete
} RequestType;
} // namespace Http

typedef std::list<std::string> KeyValueList;
typedef std::map<std::string, std::string> KeyValuePairs;

class OAuth
{
public:
    OAuth();
    ~OAuth();

    /* OAuth public methods used by twitCurl */
    void getConsumerKey( std::string& consumerKey /* out */ );
    void setConsumerKey( const std::string& consumerKey /* in */ );

    void getConsumerSecret( std::string& consumerSecret /* out */ );
    void setConsumerSecret( const std::string& consumerSecret /* in */ );

    void getOAuthTokenKey( std::string& oAuthTokenKey /* out */ );
    void setOAuthTokenKey( const std::string& oAuthTokenKey /* in */ );

    void getOAuthTokenSecret( std::string& oAuthTokenSecret /* out */ );
    void setOAuthTokenSecret( const std::string& oAuthTokenSecret /* in */ );

    void getOAuthScreenName( std::string& oAuthScreenName /* out */ );
    void setOAuthScreenName( const std::string& oAuthScreenName /* in */ );

    void getOAuthPin( std::string& oAuthPin /* out */ );
    void setOAuthPin( const std::string& oAuthPin /* in */ );

    bool getOAuthHeader( const Http::RequestType eType, /* in */
                         const std::string& rawUrl, /* in */
                         const std::string& rawData, /* in */
                         std::string& oAuthHttpHeader, /* out */
                         const bool includeOAuthVerifierPin = false /* in */ );
    bool getOAuthQueryString( const Http::RequestType eType, /* in */
                         const std::string& rawUrl, /* in */
                         const std::string& rawData, /* in */
                         std::string& oAuthQueryString, /* out */
                         const bool includeOAuthVerifierPin = false /* in */ );

    bool extractOAuthTokenKeySecret( const std::string& requestTokenResponse /* in */ );

private:

    /* OAuth data */
    std::string m_consumerKey;
    std::string m_consumerSecret;
    std::string m_oAuthTokenKey;
    std::string m_oAuthTokenSecret;
    std::string m_oAuthPin;
    std::string m_nonce;
    std::string m_timeStamp;
    std::string m_oAuthScreenName;

    /* OAuth related utility methods */
    bool buildOAuthTokenKeyValuePairs( const bool includeOAuthVerifierPin, /* in */
                                       const std::string& rawData, /* in */
                                       const std::string& oauthSignature, /* in */
                                       KeyValuePairs& keyValueMap /* out */,
                                       const bool generateTimestamp /* in */ );

    bool getStringFromOAuthKeyValuePairs( const KeyValuePairs& rawParamMap, /* in */
                                          std::string& rawParams, /* out */
                                          const std::string& paramsSeperator /* in */ );

    // Utility for getting OAuth HTTP header or query string
    bool getOAuthString( const Http::RequestType eType, /* in */
                         const std::string& rawUrl, /* in */
                         const std::string& rawData, /* in */
                         const std::string& separator /* in */,
                         std::string& oAuthString, /* out */
                         const bool includeOAuthVerifierPin /* in */ );


    bool getSignature( const Http::RequestType eType, /* in */
                       const std::string& rawUrl, /* in */
                       const KeyValuePairs& rawKeyValuePairs, /* in */
                       std::string& oAuthSignature /* out */ );

    void generateNonceTimeStamp();
};

} // namespace OAuth

#endif // __LIBOAUTHCPP_LIBOAUTHCPP_H__
