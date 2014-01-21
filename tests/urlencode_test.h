#ifndef __LIBOAUTHCPP_URLENCODE_TEST_H__
#define __LIBOAUTHCPP_URLENCODE_TEST_H__

#include "testutil.h"
#include <liboauthcpp/liboauthcpp.h>

using namespace OAuth;

namespace OAuthTest {

/** Tests URLEncode function. See http://tools.ietf.org/html/rfc3986 for
 *  details, especially Section 2. This is all based on OAuth 1.0a,
 *  which says[http://oauth.net/core/1.0a/] that all unreserved
 *  (approximately normal alphanumerics) should *not* be encoded, but
 *  *everything else* should be.
 **/
class URLEncodeTest {
public:
    static void run() {

        // Unreserved set *MUST NOT* be encoded
        ASSERT_EQUAL(
            URLEncode("abcdefghijklmnopqrstuvwxyz0123456789-._~"),
            std::string("abcdefghijklmnopqrstuvwxyz0123456789-._~"),
            "URLEncoding unreserved characters (normal alphanumerics) should be a nop"
        );

        // Everything else must be encoded

        // Reserved gen-delims
        ASSERT_EQUAL(URLEncode(":"), "%3A", "Reserved character ':' should be percent encoded");
        ASSERT_EQUAL(URLEncode("/"), "%2F", "Reserved character '/' should be percent encoded");
        ASSERT_EQUAL(URLEncode("?"), "%3F", "Reserved character '?' should be percent encoded");
        ASSERT_EQUAL(URLEncode("#"), "%23", "Reserved character '#' should be percent encoded");
        ASSERT_EQUAL(URLEncode("["), "%5B", "Reserved character ']' should be percent encoded");
        ASSERT_EQUAL(URLEncode("]"), "%5D", "Reserved character '[' should be percent encoded");
        ASSERT_EQUAL(URLEncode("@"), "%40", "Reserved character '@' should be percent encoded");
        // Reserved sub-delims
        ASSERT_EQUAL(URLEncode("!"), "%21", "Reserved character '!' should be percent encoded");
        ASSERT_EQUAL(URLEncode("$"), "%24", "Reserved character '$' should be percent encoded");
        ASSERT_EQUAL(URLEncode("%"), "%25", "Reserved character '&' should be percent encoded");
        ASSERT_EQUAL(URLEncode("&"), "%26", "Reserved character '&' should be percent encoded");
        ASSERT_EQUAL(URLEncode("'"), "%27", "Reserved character ''' should be percent encoded");
        ASSERT_EQUAL(URLEncode("("), "%28", "Reserved character '(' should be percent encoded");
        ASSERT_EQUAL(URLEncode(")"), "%29", "Reserved character ')' should be percent encoded");
        ASSERT_EQUAL(URLEncode("*"), "%2A", "Reserved character '*' should be percent encoded");
        ASSERT_EQUAL(URLEncode("+"), "%2B", "Reserved character '+' should be percent encoded");
        ASSERT_EQUAL(URLEncode(","), "%2C", "Reserved character ',' should be percent encoded");
        ASSERT_EQUAL(URLEncode(";"), "%3B", "Reserved character ';' should be percent encoded");
        ASSERT_EQUAL(URLEncode("="), "%3D", "Reserved character '=' should be percent encoded");


        // Try to cover a reasonable set of non-unreserved
        // characters to make sure we're encoding what we should. We
        // can add more here as necessary if we find errors.
        ASSERT_EQUAL(URLEncode(" "), "%20", "Non-unreserved character ' ' should be percent encoded");
        ASSERT_EQUAL(URLEncode("\""), "%22", "Non-unreserved character '\"' should be percent encoded");
        ASSERT_EQUAL(URLEncode("<"), "%3C", "Non-unreserved character '<' should be percent encoded");
        ASSERT_EQUAL(URLEncode(">"), "%3E", "Non-unreserved character '>' should be percent encoded");
        ASSERT_EQUAL(URLEncode("\\"), "%5C", "Non-unreserved character '\\' should be percent encoded");
        ASSERT_EQUAL(URLEncode("^"), "%5E", "Non-unreserved character '^' should be percent encoded");
        ASSERT_EQUAL(URLEncode("`"), "%60", "Non-unreserved character '`' should be percent encoded");
        ASSERT_EQUAL(URLEncode("{"), "%7B", "Non-unreserved character '{' should be percent encoded");
        ASSERT_EQUAL(URLEncode("|"), "%7C", "Non-unreserved character '|' should be percent encoded");
        ASSERT_EQUAL(URLEncode("}"), "%7D", "Non-unreserved character '}' should be percent encoded");
    }
};

}

#endif
