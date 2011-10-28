#include <liboauthcpp/liboauthcpp.h>
#include "HMAC_SHA1.h"
#include "base64.h"
#include "urlencode.h"
#include <cstdlib>
#include <ctime>

namespace OAuth {

namespace Defaults
{
    /* Constants */
    const int BUFFSIZE = 1024;
    const int BUFFSIZE_LARGE = 1024;
    const std::string CONSUMERKEY_KEY = "oauth_consumer_key";
    const std::string CALLBACK_KEY = "oauth_callback";
    const std::string VERSION_KEY = "oauth_version";
    const std::string SIGNATUREMETHOD_KEY = "oauth_signature_method";
    const std::string SIGNATURE_KEY = "oauth_signature";
    const std::string TIMESTAMP_KEY = "oauth_timestamp";
    const std::string NONCE_KEY = "oauth_nonce";
    const std::string TOKEN_KEY = "oauth_token";
    const std::string TOKENSECRET_KEY = "oauth_token_secret";
    const std::string VERIFIER_KEY = "oauth_verifier";
    const std::string SCREENNAME_KEY = "screen_name";

    const std::string AUTHHEADER_STRING = "Authorization: OAuth ";
};


Consumer::Consumer(const std::string& key, const std::string& secret)
 : mKey(key), mSecret(secret)
{
}



OAuth::OAuth(const Consumer& consumer)
 : mConsumer(consumer)
{
}

OAuth::OAuth(const Consumer& consumer,
    const std::string& tokenKey, const std::string& tokenSecret)
 : mConsumer(consumer),
   m_tokenKey(tokenKey),
   m_tokenSecret(tokenSecret)
{
}


/*++
* @method: OAuth::~OAuth
*
* @description: destructor
*
* @input: none
*
* @output: none
*
*--*/
OAuth::~OAuth()
{
}



/*++
* @method: OAuth::getOAuthScreenName
*
* @description: this method gives authorized user's screenname
*
* @input: none
*
* @output: screen name
*
*--*/
void OAuth::getOAuthScreenName( std::string& oAuthScreenName )
{
    oAuthScreenName = m_oAuthScreenName;
}

/*++
* @method: OAuth::setOAuthScreenName
*
* @description: this method sets authorized user's screenname
*
* @input: screen name
*
* @output: none
*
*--*/
void OAuth::setOAuthScreenName( const std::string& oAuthScreenName )
{
    m_oAuthScreenName = oAuthScreenName;
}

/*++
* @method: OAuth::generateNonceTimeStamp
*
* @description: this method generates nonce and timestamp for OAuth header
*
* @input: none
*
* @output: none
*
* @remarks: internal method
*
*--*/
void OAuth::generateNonceTimeStamp()
{
    char szTime[Defaults::BUFFSIZE];
    char szRand[Defaults::BUFFSIZE];
    memset( szTime, 0, Defaults::BUFFSIZE );
    memset( szRand, 0, Defaults::BUFFSIZE );
    srand( time( NULL ) );
    sprintf( szRand, "%x", rand()%1000 );
    sprintf( szTime, "%ld", time( NULL ) );

    m_nonce.assign( szTime );
    m_nonce.append( szRand );
    m_timeStamp.assign( szTime );
}

/*++
* @method: OAuth::buildOAuthTokenKeyValuePairs
*
* @description: this method prepares key-value pairs required for OAuth header
*               and signature generation.
*
* @input: includeOAuthVerifierPin - flag to indicate whether oauth_verifer key-value
*                                   pair needs to be included. oauth_verifer is only
*                                   used during exchanging request token with access token.
*         rawData - url encoded data. this is used during signature generation.
*         oauthSignature - base64 and url encoded OAuth signature.
*         generateTimestamp - If true, then generate new timestamp for nonce.
*
* @output: keyValueMap - map in which key-value pairs are populated
*
* @remarks: internal method
*
*--*/
bool OAuth::buildOAuthTokenKeyValuePairs( const bool includeOAuthVerifierPin,
                                          const std::string& rawData,
                                          const std::string& oauthSignature,
                                          KeyValuePairs& keyValueMap,
                                          const bool generateTimestamp )
{
    /* Generate nonce and timestamp if required */
    if( generateTimestamp )
    {
        generateNonceTimeStamp();
    }

    /* Consumer key and its value */
    keyValueMap[Defaults::CONSUMERKEY_KEY] = mConsumer.key();

    /* Nonce key and its value */
    keyValueMap[Defaults::NONCE_KEY] = m_nonce;

    /* Signature if supplied */
    if( oauthSignature.length() )
    {
        keyValueMap[Defaults::SIGNATURE_KEY] = oauthSignature;
    }

    /* Signature method, only HMAC-SHA1 as of now */
    keyValueMap[Defaults::SIGNATUREMETHOD_KEY] = std::string( "HMAC-SHA1" );

    /* Timestamp */
    keyValueMap[Defaults::TIMESTAMP_KEY] = m_timeStamp;

    /* Token */
    if( m_tokenKey.length() )
    {
        keyValueMap[Defaults::TOKEN_KEY] = m_tokenKey;
    }

    /* Verifier */
    if( includeOAuthVerifierPin && m_pin.length() )
    {
        keyValueMap[Defaults::VERIFIER_KEY] = m_pin;
    }

    /* Version */
    keyValueMap[Defaults::VERSION_KEY] = std::string( "1.0" );

    /* Data if it's present */
    if( rawData.length() )
    {
        /* Data should already be urlencoded once */
        std::string dummyStrKey;
        std::string dummyStrValue;
        size_t nPos = rawData.find_first_of( "=" );
        if( std::string::npos != nPos )
        {
            dummyStrKey = rawData.substr( 0, nPos );
            dummyStrValue = rawData.substr( nPos + 1 );
            keyValueMap[dummyStrKey] = dummyStrValue;
        }
    }

    return ( keyValueMap.size() ) ? true : false;
}

/*++
* @method: OAuth::getSignature
*
* @description: this method calculates HMAC-SHA1 signature of OAuth header
*
* @input: eType - HTTP request type
*         rawUrl - raw url of the HTTP request
*         rawKeyValuePairs - key-value pairs containing OAuth headers and HTTP data
*
* @output: oAuthSignature - base64 and url encoded signature
*
* @remarks: internal method
*
*--*/
bool OAuth::getSignature( const Http::RequestType eType,
                          const std::string& rawUrl,
                          const KeyValuePairs& rawKeyValuePairs,
                          std::string& oAuthSignature )
{
    std::string rawParams;
    std::string paramsSeperator;
    std::string sigBase;

    /* Initially empty signature */
    oAuthSignature.assign( "" );

    /* Build a string using key-value pairs */
    paramsSeperator = "&";
    getStringFromOAuthKeyValuePairs( rawKeyValuePairs, rawParams, paramsSeperator );

    /* Start constructing base signature string. Refer http://dev.twitter.com/auth#intro */
    switch( eType )
    {
      case Http::Get:
        {
            sigBase.assign( "GET&" );
        }
        break;

      case Http::Post:
        {
            sigBase.assign( "POST&" );
        }
        break;

      case Http::Delete:
        {
            sigBase.assign( "DELETE&" );
        }
        break;

    default:
        {
            return false;
        }
        break;
    }
    sigBase.append( urlencode( rawUrl ) );
    sigBase.append( "&" );
    sigBase.append( urlencode( rawParams ) );

    /* Now, hash the signature base string using HMAC_SHA1 class */
    CHMAC_SHA1 objHMACSHA1;
    std::string secretSigningKey;
    unsigned char strDigest[Defaults::BUFFSIZE_LARGE];

    memset( strDigest, 0, Defaults::BUFFSIZE_LARGE );

    /* Signing key is composed of consumer_secret&token_secret */
    secretSigningKey.assign( mConsumer.secret() );
    secretSigningKey.append( "&" );
    if( m_tokenSecret.length() )
    {
        secretSigningKey.append( m_tokenSecret );
    }

    objHMACSHA1.HMAC_SHA1( (unsigned char*)sigBase.c_str(),
                           sigBase.length(),
                           (unsigned char*)secretSigningKey.c_str(),
                           secretSigningKey.length(),
                           strDigest );

    /* Do a base64 encode of signature */
    std::string base64Str = base64_encode( strDigest, 20 /* SHA 1 digest is 160 bits */ );

    /* Do an url encode */
    oAuthSignature = urlencode( base64Str );

    return ( oAuthSignature.length() ) ? true : false;
}

/*++
* @method: OAuth::getOAuthHeader
*
* @description: this method builds OAuth header that should be used in HTTP requests
*
* @input: eType - HTTP request type
*         rawUrl - raw url of the HTTP request
*         rawData - HTTP data
*         includeOAuthVerifierPin - flag to indicate whether or not oauth_verifier needs to included
*                                   in OAuth header
*
* @output: oAuthHttpHeader - OAuth header
*
*--*/
bool OAuth::getOAuthHeader( const Http::RequestType eType,
                            const std::string& rawUrl,
                            const std::string& rawData,
                            std::string& oAuthHttpHeader,
                            const bool includeOAuthVerifierPin )
{

    bool got_auth_string = getOAuthString(eType, rawUrl, rawData, ",", oAuthHttpHeader, includeOAuthVerifierPin);
    oAuthHttpHeader = Defaults::AUTHHEADER_STRING + oAuthHttpHeader;
    return got_auth_string;
}
/*++
* @method: OAuth::getOAuthQueryString
*
* @description: this method builds OAuth query string that should be used in
* HTTP requests.
*
* @note: This omits the ? part to allow you to easily combine it with other
* query strings.
*
* @input: eType - HTTP request type
*         rawUrl - raw url of the HTTP request
*         rawData - HTTP data
*         includeOAuthVerifierPin - flag to indicate whether or not oauth_verifier needs to included
*                                   in OAuth header
*
* @output: oAuthQueryString - OAuth query string
*
*--*/
bool OAuth::getOAuthQueryString( const Http::RequestType eType,
                            const std::string& rawUrl,
                            const std::string& rawData,
                            std::string& oAuthQueryString,
                            const bool includeOAuthVerifierPin )
{
    return getOAuthString(eType, rawUrl, rawData, "&", oAuthQueryString, includeOAuthVerifierPin);
}

bool OAuth::getOAuthString( const Http::RequestType eType,
                            const std::string& rawUrl,
                            const std::string& rawData,
                            const std::string& separator,
                            std::string& oAuthString,
                            const bool includeOAuthVerifierPin )
{
    KeyValuePairs rawKeyValuePairs;
    std::string rawParams;
    std::string oauthSignature;
    std::string paramsSeperator;
    std::string pureUrl( rawUrl );

    /* Clear header string initially */
    oAuthString = "";
    rawKeyValuePairs.clear();

    /* If URL itself contains ?key=value, then extract and put them in map */
    size_t nPos = rawUrl.find_first_of( "?" );
    if( std::string::npos != nPos )
    {
        /* Get only URL */
        pureUrl = rawUrl.substr( 0, nPos );

        /* Get only key=value data part */
        std::string dataPart = rawUrl.substr( nPos + 1 );

        /* This dataPart can contain many key value pairs: key1=value1&key2=value2&key3=value3 */
        size_t nSep = std::string::npos;
        size_t nPos2 = std::string::npos;
        std::string dataKeyVal;
        std::string dataKey;
        std::string dataVal;
        while( std::string::npos != ( nSep = dataPart.find_first_of("&") ) )
        {
            /* Extract first key=value pair */
            dataKeyVal = dataPart.substr( 0, nSep );

            /* Split them */
            nPos2 = dataKeyVal.find_first_of( "=" );
            if( std::string::npos != nPos2 )
            {
                dataKey = dataKeyVal.substr( 0, nPos2 );
                dataVal = dataKeyVal.substr( nPos2 + 1 );

                /* Put this key=value pair in map */
                rawKeyValuePairs[dataKey] = urlencode( dataVal );
            }
            dataPart = dataPart.substr( nSep + 1 );
        }

        /* For the last key=value */
        dataKeyVal = dataPart.substr( 0, nSep );

        /* Split them */
        nPos2 = dataKeyVal.find_first_of( "=" );
        if( std::string::npos != nPos2 )
        {
            dataKey = dataKeyVal.substr( 0, nPos2 );
            dataVal = dataKeyVal.substr( nPos2 + 1 );

            /* Put this key=value pair in map */
            rawKeyValuePairs[dataKey] = urlencode( dataVal );
        }
    }

    /* Build key-value pairs needed for OAuth request token, without signature */
    buildOAuthTokenKeyValuePairs( includeOAuthVerifierPin, rawData, std::string( "" ), rawKeyValuePairs, true );

    /* Get url encoded base64 signature using request type, url and parameters */
    getSignature( eType, pureUrl, rawKeyValuePairs, oauthSignature );

    /* Now, again build key-value pairs with signature this time */
    buildOAuthTokenKeyValuePairs( includeOAuthVerifierPin, std::string( "" ), oauthSignature, rawKeyValuePairs, false );

    /* Get OAuth header in string format */
    getStringFromOAuthKeyValuePairs( rawKeyValuePairs, rawParams, separator );

    /* Build authorization header */
    oAuthString = rawParams;

    return ( oAuthString.length() ) ? true : false;
}

/*++
* @method: OAuth::getStringFromOAuthKeyValuePairs
*
* @description: this method builds a sorted string from key-value pairs
*
* @input: rawParamMap - key-value pairs map
*         paramsSeperator - sepearator, either & or ,
*
* @output: rawParams - sorted string of OAuth parameters
*
* @remarks: internal method
*
*--*/
bool OAuth::getStringFromOAuthKeyValuePairs( const KeyValuePairs& rawParamMap,
                                             std::string& rawParams,
                                             const std::string& paramsSeperator )
{
    rawParams.assign( "" );
    if( rawParamMap.size() )
    {
        KeyValueList keyValueList;
        std::string dummyStr;

        /* Push key-value pairs to a list of strings */
        keyValueList.clear();
        KeyValuePairs::const_iterator itMap = rawParamMap.begin();
        for( ; itMap != rawParamMap.end(); itMap++ )
        {
            dummyStr.assign( itMap->first );
            dummyStr.append( "=" );
            if( paramsSeperator == "," )
            {
                dummyStr.append( "\"" );
            }
            dummyStr.append( itMap->second );
            if( paramsSeperator == "," )
            {
                dummyStr.append( "\"" );
            }
            keyValueList.push_back( dummyStr );
        }

        /* Sort key-value pairs based on key name */
        keyValueList.sort();

        /* Now, form a string */
        dummyStr.assign( "" );
        KeyValueList::iterator itKeyValue = keyValueList.begin();
        for( ; itKeyValue != keyValueList.end(); itKeyValue++ )
        {
            if( dummyStr.length() )
            {
                dummyStr.append( paramsSeperator );
            }
            dummyStr.append( itKeyValue->c_str() );
        }
        rawParams.assign( dummyStr );
    }
    return ( rawParams.length() ) ? true : false;
}

/*++
* @method: OAuth::extractOAuthTokenKeySecret
*
* @description: this method extracts oauth token key and secret from
*               HTTP response
*
* @input: requestTokenResponse - response from OAuth server
*
* @output: none
*
*--*/
bool OAuth::extractOAuthTokenKeySecret( const std::string& requestTokenResponse )
{
    if( requestTokenResponse.length() )
    {
        size_t nPos = std::string::npos;
        std::string strDummy;

        /* Get oauth_token key */
        nPos = requestTokenResponse.find( Defaults::TOKEN_KEY );
        if( std::string::npos != nPos )
        {
            nPos = nPos + Defaults::TOKEN_KEY.length() + strlen( "=" );
            strDummy = requestTokenResponse.substr( nPos );
            nPos = strDummy.find( "&" );
            if( std::string::npos != nPos )
            {
                m_tokenKey = strDummy.substr( 0, nPos );
            }
        }

        /* Get oauth_token_secret */
        nPos = requestTokenResponse.find( Defaults::TOKENSECRET_KEY );
        if( std::string::npos != nPos )
        {
            nPos = nPos + Defaults::TOKENSECRET_KEY.length() + strlen( "=" );
            strDummy = requestTokenResponse.substr( nPos );
            nPos = strDummy.find( "&" );
            if( std::string::npos != nPos )
            {
                m_tokenSecret = strDummy.substr( 0, nPos );
            }
        }

        /* Get screen_name */
        nPos = requestTokenResponse.find( Defaults::SCREENNAME_KEY );
        if( std::string::npos != nPos )
        {
            nPos = nPos + Defaults::SCREENNAME_KEY.length() + strlen( "=" );
            strDummy = requestTokenResponse.substr( nPos );
            m_oAuthScreenName = strDummy;
        }
    }
    return true;
}

} // namespace OAuth
