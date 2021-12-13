
import XCTest
import Casbin

final class KeyMatchTests: XCTestCase {
    func testKeyMatch() {
        XCTAssertTrue(Util.keyMatch("/foo/bar", "/foo/*"))
        XCTAssertTrue(!Util.keyMatch("/bar/foo", "/foo/*"))
        XCTAssertTrue(Util.keyMatch("/bar", "/ba*"))
    }
    func testRegexMatch() {
        XCTAssertTrue(Util.regexMatch("foobar", "^foo*"))
        XCTAssertFalse(Util.regexMatch("barfoo", "^foo*"))
    }
    func testKeyMatch2() {
        XCTAssertTrue(Util.keyMatch2("/foo/bar", "/foo/*"))
        XCTAssertTrue(Util.keyMatch2("/foo/baz", "/foo/:bar"))
        XCTAssertTrue(Util.keyMatch2("/foo/baz", "/:foo/:bar"))
        XCTAssertTrue(Util.keyMatch2("/foo/baz/foo", "/foo/:bar/foo"))
        XCTAssertTrue(!Util.keyMatch2("/baz", "/foo"))
    }
    func testKeyMatch3() {
        XCTAssertTrue(Util.keyMatch3("/foo/bar", "/foo/*"))
        XCTAssertTrue(Util.keyMatch3("/foo/baz", "/foo/{bar}"))
        XCTAssertTrue(Util.keyMatch3("/foo/baz/foo", "/foo/{bar}/foo"))
        XCTAssertTrue(!Util.keyMatch3("/baz", "/foo"))
    }
    func testIpMatch() {
        XCTAssertTrue(Util.ipMatch("::1", "::0:1"))
        XCTAssertTrue(Util.ipMatch("192.168.1.1", "192.168.1.1"))
        XCTAssertTrue(Util.ipMatch("192.168.2.123", "192.168.2.0/24"))
        XCTAssertTrue(Util.ipMatch("192.168.2.123", "192.168.2.123/16"))
        XCTAssertFalse(Util.ipMatch("::1", "127.0.0.2"))
        XCTAssertFalse(Util.ipMatch("192.168.2.189", "192.168.1.134/26"))
    }
    func testglobMatch() {
        XCTAssertTrue(Util.globMatch("/foo", "/foo"))
        XCTAssertTrue(Util.globMatch("/foo", "/foo*"))
        XCTAssertFalse(Util.globMatch("/foo", "/foo/*"))
        XCTAssertFalse(Util.globMatch("/foo/bar", "/foo"))
        XCTAssertFalse(Util.globMatch("/foo/bar", "/foo*"))
        XCTAssertTrue(Util.globMatch("/foo/bar", "/foo/*"))
        XCTAssertFalse(Util.globMatch("/foobar", "*/foo"))
        XCTAssertFalse(Util.globMatch("/prefix/foobar", "*/foo/*"))
    }
}


