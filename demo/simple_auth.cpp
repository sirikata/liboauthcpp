#include <iostream>
#include <string>
#include <liboauthcpp/liboauthcpp.h>

/* These are input settings that make this demo actually work -- you need to get
 * these, e.g. by referring to the Twitter documentation and by registering an
 * application with them. Here we have examples from Twitter.
 */
std::string consumer_key = "my_key_from_twitter";
std::string consumer_secret = "my_secret_from_twitter";
std::string request_token_url = "http://twitter.com/oauth/request_token";
std::string authorize_url = "http://twitter.com/oauth/authorize";
std::string access_token_url = "http://twitter.com/oauth/access_token";


std::string getUserString(std::string prompt) {
    std::cout << prompt << " ";

    std::string res;
    std::cin >> res;
    std::cout << std::endl;
    return res;
}

int main(int argc, char** argv) {

    // Initialization
    oAuth oauth;
    oauth.setConsumerKey( consumer_key );
    oauth.setConsumerSecret( consumer_secret );

    // Step 1: Get a request token. This is a temporary token that is used for
    // having the user authorize an access token and to sign the request to
    // obtain said access token.
    std::string oAuthQueryString;
    if (!oauth.getOAuthQueryString( eOAuthHttpGet, request_token_url, std::string( "" ), oAuthQueryString )) {
        std::cout << "getOAuthQueryString failed...";
        return -1;
    }
    std::cout << "Enter the following in your browser to get the request token: " << std::endl;
    std::cout << request_token_url << "?" << oAuthQueryString << std::endl;
    std::cout << std::endl;

    // Extract the token and token_secret from the response
    std::string request_token_resp = getUserString("Enter the response:");
    oauth.extractOAuthTokenKeySecret( request_token_resp );

    // Get access token and secret from OAuth object
    std::string oAuthTokenKey, oAuthTokenSecret;
    oauth.getOAuthTokenKey( oAuthTokenKey );
    oauth.getOAuthTokenSecret( oAuthTokenSecret );
    std::cout << "Request Token:" << std::endl;
    std::cout << "    - oauth_token        = " << oAuthTokenKey << std::endl;
    std::cout << "    - oauth_token_secret = " << oAuthTokenSecret << std::endl;
    std::cout << std::endl;

    // Step 2: Redirect to the provider. Since this is a CLI script we
    // do not redirect. In a web application you would redirect the
    // user to the URL below.
    std::cout << "Go to the following link in your browser to authorize this application on a user's account:" << std::endl;
    std::cout << authorize_url << "?oauth_token=" << oAuthTokenKey << std::endl;

    // After the user has granted access to you, the consumer, the
    // provider will redirect you to whatever URL you have told them
    // to redirect to. You can usually define this in the
    // oauth_callback argument as well.
    std::string pin = getUserString("What is the PIN?");
    oauth.setOAuthPin(pin);

    // Step 3: Once the consumer has redirected the user back to the
    // oauth_callback URL you can request the access token the user
    // has approved. You use the request token to sign this
    // request. After this is done you throw away the request token
    // and use the access token returned. You should store the oauth
    // token and token secret somewhere safe, like a database, for
    // future use.
    if (!oauth.getOAuthQueryString( eOAuthHttpGet, access_token_url, std::string( "" ), oAuthQueryString, true ) )
    std::cout << "Enter the following in your browser to get the final access token & secret: " << std::endl;
    std::cout << access_token_url << "?" << oAuthQueryString;
    std::cout << std::endl;

    // Once they've come back from the browser, extract the token and token_secret from the response
    std::string access_token_resp = getUserString("Enter the response:");
    oauth.extractOAuthTokenKeySecret( access_token_resp );

    oauth.getOAuthTokenKey( oAuthTokenKey );
    oauth.getOAuthTokenSecret( oAuthTokenSecret );
    std::cout << "Access token:" << std::endl;
    std::cout << "    - oauth_token        = " << oAuthTokenKey << std::endl;
    std::cout << "    - oauth_token_secret = " << oAuthTokenSecret << std::endl;
    std::cout << std::endl;
    std::cout << "You may now access protected resources using the access tokens above." << std::endl;
    std::cout << std::endl;

    return 0;
}
