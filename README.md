liboauthcpp
-----------

liboauthcpp is a pure C++ library for performing OAuth requests. It
doesn't contain any networking code -- you provide for performing HTTP
requests yourself, however you like -- instead focusing on performing
OAuth-specific functionality and providing a nice interface for it.
If you already have infrastructure for making HTTP requests and are
looking to add OAuth support, liboauthcpp is for you.

liboauthcpp currently implements OAuth 1.0a (see
http://tools.ietf.org/html/rfc5849).

Requirements
------------

You should only need:

 * CMake
 * A C++ compiler for your platform (e.g. g++, Microsoft Visual C++)

Compiling
---------

The build process is simple:

    cd liboauthcpp
    cd build
    cmake .
    make            # or open Visual Studio and build the solution

If your own project uses CMake you can also include
build/CMakeLists.txt directly into your project and reference the
target "oauthcpp", a static library, in your project.

Demos
-----
There are two demos included in the demos/ directory, and they are built by
default with the instructions above. In both, you enter key/secret information
and it generates URLs for you to visit (in a browser) and copy data back into
the program.

simple_auth should be executed first. It starts with only a consumer key and
secret and performs 3-legged auth: you enter in consumer keys, it generates URLs
to authenticate the user and generate access tokens. It requires 3 steps:
request_token, authorize, and access_token (which correspond the URLs
accessed). At the end of this process, you'll be provided an access key/secret
pair which you can use to access actual resources.

simple_request actually does something useful now that your application is
authorized. Enter your consumer key/secret and the access key/secret from
simple_auth (or which you've generated elsewhere) and it will generate a URL you
can use to access your home timeline in JSON format. It adds a parameter to ask
for only 5 entries (demonstrating that signing works properly over additional
query parameters). This is a one-step process -- it just gives you the URL and
you get the results in your browser.

In both, the URLs accessed are specified at the top of the demo
files. simple_auth requires URLs for request_token, authorize_url, and
access_token. Some providers require additional parameters (notably an
oauth_callback for Twitter, even if its out of band, or oob), which you can also
specify in that location. simple_request only needs the URL of the resource
being accessed (i.e. the URL for the home_timeline JSON data used by default in
the demo), with optional parameters stored as a query string.

Both demos only use GET requests with query strings, but all HTTP methods
(e.g. POST, PUT, DELETE) and approaches to sending parameters (e.g. HTTP
headers, url-encoded body) should be supported in the API.

License
-------

liboauthcpp is MIT licensed. See the LICENSE file for more details.

liboauthcpp is mostly taken from libtwitcurl
(http://code.google.com/p/twitcurl/), which is similarly licensed. It
mostly serves to isolate the OAuth code from libtwitcurl's Twitter and
cURL specific code.

libtwitcurl also borrowed code from other projects:
twitcurl uses HMAC_SHA1 from http://www.codeproject.com/KB/recipes/HMACSHA1class.aspx
twitcurl uses base64 from http://www.adp-gmbh.ch/cpp/common/base64.html
