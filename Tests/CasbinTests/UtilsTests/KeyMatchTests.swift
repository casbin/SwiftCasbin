import Testing
import Casbin

@Suite("Key/Glob/IP match utilities", .timeLimit(.minutes(1)))
struct KeyMatchTests {
    @Test("keyMatch")
    func testKeyMatch() {
        #expect(Util.keyMatch("/foo/bar", "/foo/*"))
        #expect(!Util.keyMatch("/bar/foo", "/foo/*"))
        #expect(Util.keyMatch("/bar", "/ba*"))
    }

    @Test("regexMatch")
    func testRegexMatch() {
        #expect(Util.regexMatch("foobar", "^foo*"))
        #expect(!Util.regexMatch("barfoo", "^foo*"))
    }

    @Test("keyMatch2 path params")
    func testKeyMatch2() {
        #expect(Util.keyMatch2("/foo/bar", "/foo/*"))
        #expect(Util.keyMatch2("/foo/baz", "/foo/:bar"))
        #expect(Util.keyMatch2("/foo/baz", "/:foo/:bar"))
        #expect(Util.keyMatch2("/foo/baz/foo", "/foo/:bar/foo"))
        #expect(!Util.keyMatch2("/baz", "/foo"))
    }

    @Test("keyMatch3 braces params")
    func testKeyMatch3() {
        #expect(Util.keyMatch3("/foo/bar", "/foo/*"))
        #expect(Util.keyMatch3("/foo/baz", "/foo/{bar}"))
        #expect(Util.keyMatch3("/foo/baz/foo", "/foo/{bar}/foo"))
        #expect(!Util.keyMatch3("/baz", "/foo"))
    }

    @Test("ipMatch IPv4/IPv6 + CIDR")
    func testIpMatch() {
        #expect(Util.ipMatch("::1", "::0:1"))
        #expect(Util.ipMatch("192.168.1.1", "192.168.1.1"))
        #expect(Util.ipMatch("192.168.2.123", "192.168.2.0/24"))
        #expect(Util.ipMatch("192.168.2.123", "192.168.2.123/16"))
        #expect(!Util.ipMatch("::1", "127.0.0.2"))
        #expect(!Util.ipMatch("192.168.2.189", "192.168.1.134/26"))
    }

    @Test("globMatch patterns")
    func testglobMatch() {
        #expect(Util.globMatch("/foo", "/foo"))
        #expect(Util.globMatch("/foo", "/foo*"))
        #expect(!Util.globMatch("/foo", "/foo/*"))
        #expect(!Util.globMatch("/foo/bar", "/foo"))
        #expect(!Util.globMatch("/foo/bar", "/foo*"))
        #expect(Util.globMatch("/foo/bar", "/foo/*"))
        #expect(!Util.globMatch("/foobar", "/foo"))
        #expect(Util.globMatch("/foobar", "/foo*"))
        #expect(!Util.globMatch("/foobar", "/foo/*"))
        #expect(Util.globMatch("/foo", "*/foo"))
        #expect(Util.globMatch("/foo", "*/foo*"))
        #expect(!Util.globMatch("/foo", "*/foo/*"))
        #expect(!Util.globMatch("/foo/bar", "*/foo"))
        #expect(!Util.globMatch("/foo/bar", "*/foo*"))
        #expect(Util.globMatch("/foo/bar", "*/foo/*"))
        #expect(!Util.globMatch("/foobar", "*/foo"))
        #expect(Util.globMatch("/foobar", "*/foo*"))
        #expect(!Util.globMatch("/foobar", "*/foo/*"))
        #expect(!Util.globMatch("/prefix/foo", "*/foo"))
        #expect(!Util.globMatch("/prefix/foo", "*/foo*"))
        #expect(!Util.globMatch("/prefix/foo", "*/foo/*"))
        #expect(!Util.globMatch("/prefix/foo/bar", "*/foo"))
        #expect(!Util.globMatch("/prefix/foo/bar", "*/foo*"))
        #expect(!Util.globMatch("/prefix/foo/bar", "*/foo/*"))
        #expect(!Util.globMatch("/prefix/foobar", "*/foo"))
        #expect(!Util.globMatch("/prefix/foobar", "*/foo*"))
        #expect(!Util.globMatch("/prefix/foobar", "*/foo/*"))
        #expect(!Util.globMatch("/prefix/subprefix/foo", "*/foo"))
        #expect(!Util.globMatch("/prefix/subprefix/foo", "*/foo*"))
        #expect(!Util.globMatch("/prefix/subprefix/foo", "*/foo/*"))
        #expect(!Util.globMatch("/prefix/subprefix/foo/bar", "*/foo"))
        #expect(!Util.globMatch("/prefix/subprefix/foo/bar", "*/foo*"))
        #expect(!Util.globMatch("/prefix/subprefix/foo/bar", "*/foo/*"))
        #expect(!Util.globMatch("/prefix/subprefix/foobar", "*/foo"))
        #expect(!Util.globMatch("/prefix/subprefix/foobar", "*/foo*"))
        #expect(!Util.globMatch("/prefix/subprefix/foobar", "*/foo/*"))
    }
}
