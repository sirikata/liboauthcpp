#ifndef __LIBOAUTHCPP_LIBOAUTHCPP_H__
#define __LIBOAUTHCPP_LIBOAUTHCPP_H__

#include <string>
#include <list>
#include <map>
#include <stdexcept>

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


class ParseError : public std::runtime_error {
public:
    ParseError(const std::string msg)
     : std::runtime_error(msg)
    {}
};

/** A consumer of OAuth-protected services. It is the client to an
 *  OAuth service provider and is usually registered with the service
 *  provider, resulting in a consumer *key* and *secret* used to
 *  identify the consumer. The key is included in all requests and the
 *  secret is used to *sign* all requests.  Signed requests allow the
 *  consumer to securely perform operations, including kicking off
 *  three-legged authentication to enable performing operations on
 *  behalf of a user of the service provider.
 */
class Consumer {
public:
    Consumer(const std::string& key, const std::string& secret);

    const std::string& key() const { return mKey; }
    const std::string& secret() const { return mSecret; }

private:
    const std::string mKey;
    const std::string mSecret;
};

/** An OAuth credential used to request authorization or a protected
 *  resource.
 *
 *  Tokens in OAuth comprise a *key* and a *secret*. The key is
 *  included in requests to identify the token being used, but the
 *  secret is used only in the signature, to prove that the requester
 *  is who the server gave the token to.
 *
 *  When first negotiating the authorization, the consumer asks for a
 *  *request token* that the live user authorizes with the service
 *  provider. The consumer then exchanges the request token for an
 *  *access token* that can be used to access protected resources.
 */
class Token {
public:
    Token(const std::string& key, const std::string& secret);
    Token(const std::string& key, const std::string& secret, const std::string& pin);

    const std::string& key() const { return mKey; }
    const std::string& secret() const { return mSecret; }

    const std::string& pin() const { return mPin; }
    void setPin(const std::string& pin_) { mPin = pin_; }

private:
    const std::string mKey;
    const std::string mSecret;
    std::string mPin;
};

class OAuth
{
public:
    /** Construct an OAuth signer using only a consumer key and
     *  secret. You can use this to start a three-legged
     *  authentication (to acquire an access token for a user) or for
     *  simple two-legged authentication (signing with empty access
     *  token info).
     *
     *  \param consumer Consumer information. The caller must ensure
     *         it remains valid during the lifetime of this object
     */
    OAuth(const Consumer* consumer);
    /** Construct an OAuth signer with consumer key and secret (yours)
     *  and access token key and secret (acquired and stored during
     *  three-legged authentication).
     *
     *  \param consumer Consumer information. The caller must ensure
     *         it remains valid during the lifetime of this object
     *  \param token Access token information. The caller must ensure
     *         it remains valid during the lifetime of this object
     */
    OAuth(const Consumer* consumer, const Token* token);

    ~OAuth();

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

    Token extractToken( const std::string& requestTokenResponse /* in */ );

private:
    /** Disable default constructur -- must provide consumer
     * information.
     */
    OAuth();

    /* OAuth data */
    const Consumer* mConsumer;
    const Token* mToken;
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
