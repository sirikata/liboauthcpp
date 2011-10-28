#include <iostream>
#include <string>
#include <liboauthcpp/liboauthcpp.h>

/* These are input settings that make this demo actually work -- you need to get
 * these, e.g. by referring to the Twitter documentation and by registering an
 * application with them. Here we have examples from Twitter.
 */
std::string consumer_key = "my_key_from_twitter";
std::string consumer_secret = "my_secret_from_twitter";
std::string oauth_token = "user_specific_oauth_token";
std::string oauth_token_secret = "user_specific_oauth_token_secret";
// An example resource to be accessed, along with parameters for the request
std::string oauth_protected_resource = "https://api.twitter.com/1/statuses/home_timeline.json";
std::string oauth_protected_resource_params = "count=5";

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
    // We assume you have gotten the access token. You may have e.g., used
    // simple_auth to get it.
    oauth.setOAuthTokenKey( oauth_token );
    oauth.setOAuthTokenSecret( oauth_token_secret );

    // Get the query string. Note that we pass in the URL as if we were , but
    // *the output query string includes the parameters you passed in*. Below,
    // we append the result only to the base URL, not the entire URL we passed
    // in here.
    std::string oAuthQueryString;
    if (!oauth.getOAuthQueryString( eOAuthHttpGet, oauth_protected_resource + "?" + oauth_protected_resource_params, std::string(""), oAuthQueryString)) {
        std::cout << "getOAuthQueryString failed...";
        return -1;
    }

    std::cout << "Enter the following in your browser to access the resource: " << std::endl;
    std::cout << oauth_protected_resource << "?" << oAuthQueryString << std::endl;
    std::cout << std::endl;

    return 0;
}
