#include <iostream>
#include "testutil.h"
#include "urlencode_test.h"
#include "parsekeyvaluepairs_test.h"
#include "request_test.h"

using namespace OAuthTest;

int main(int argc, char** argv) {
    URLEncodeTest::run();
    ParseKeyValuePairsTest::run();
    RequestTest::run();

    return TestUtil::summary();
}
