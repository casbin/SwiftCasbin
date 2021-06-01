
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
}


