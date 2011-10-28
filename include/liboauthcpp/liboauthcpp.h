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
    /** Default constructor. Does not initialize any OAuth parameters
     *  -- you need to manually set the consumer key and secret before
     *  signing any requests.
     */
    OAuth();
    /** Construct an OAuth signer using only a consumer key and
     *  secret. You can use this to start a three-legged
     *  authentication (to acquire an access token for a user) or for
     *  simple two-legged authentication (signing with empty access
     *  token info).
     */
    OAuth(const std::string& consumerKey, const std::string& consumerSecret);
    /** Construct an OAuth signer with consumer key and secret (yours)
     *  and access token key and secret (acquired and stored during
     *  three-legged authentication).
     */
    OAuth(const std::string& consumerKey, const std::string& consumerSecret,
        const std::string& tokenKey, const std::string& tokenSecret);

    ~OAuth();

    const std::string& getConsumerKey() { return m_consumerKey; }
    void setConsumerKey(const std::string& consumerKey) { m_consumerKey = consumerKey; }

    const std::string& getConsumerSecret() { return m_consumerSecret; }
    void setConsumerSecret(const std::string& consumerSecret) { m_consumerSecret = consumerSecret; }

    const std::string& getTokenKey() { return m_tokenKey; }
    void setTokenKey(const std::string& tokenKey) { m_tokenKey = tokenKey; }

    const std::string& getTokenSecret() { return m_tokenSecret; }
    void setTokenSecret(const std::string& tokenSecret) { m_tokenSecret = tokenSecret; }

    const std::string& getPin() { return m_pin; }
    void setPin(const std::string& pin) { m_pin = pin; }

    void getOAuthScreenName( std::string& oAuthScreenName /* out */ );
    void setOAuthScreenName( const std::string& oAuthScreenName /* in */ );

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
    std::string m_tokenKey;
    std::string m_tokenSecret;
    std::string m_pin;
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
