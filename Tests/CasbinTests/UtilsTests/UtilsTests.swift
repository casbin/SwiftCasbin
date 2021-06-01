
import XCTest
import Casbin

final class UtilsTests: XCTestCase {
    func testWscapeAssertion() {
        let s = "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act"
        let exp = "g(r_sub, p_sub) && r_obj == p_obj && r_act == p_act"
        XCTAssertEqual(exp, Util.escapeAssertion(s))
        
        let s1 = "g(r2.sub, p2.sub) && r2.obj == p2.obj && r2.act == p2.act"
        let exp1 = "g(r2_sub, p2_sub) && r2_obj == p2_obj && r2_act == p2_act"
        XCTAssertEqual(exp1, Util.escapeAssertion(s1))
    }
    func testCsvParse1() {
        XCTAssertEqual(Util.parseCsvLine(line: "alice, domain1, data1, action1"), ["alice","domain1","data1","action1"])
    }
    func testCsvParse2() {
        XCTAssertEqual(Util.parseCsvLine(line: #"alice, "domain1, domain2", data1 , action1"#), ["alice","domain1, domain2","data1","action1"])
    }
    func testCsvParse3() {
        XCTAssertEqual(Util.parseCsvLine(line: ","), nil)
    }
    func testCsvParse4() {
        XCTAssertEqual(Util.parseCsvLine(line: ""), nil)
        XCTAssertEqual(Util.parseCsvLine(line: "#"), nil)
        XCTAssertEqual(Util.parseCsvLine(line: " #"), nil)
        XCTAssertEqual(Util.parseCsvLine(line: "\" "), ["\""])
        XCTAssertEqual(Util.parseCsvLine(line: "\" alice"), ["\" alice"])
        XCTAssertEqual(Util.parseCsvLine(line: "alice, \"domain1, domain2"), ["alice","\"domain1, domain2"])
        XCTAssertEqual(Util.parseCsvLine(line: "\"\""), [""])
        XCTAssertEqual(Util.parseCsvLine(line: "r.sub.Status == \"ACTIVE\", /data1, read"), ["r.sub.Status == \"ACTIVE\"","/data1","read"])
        
    }
    func testCsvParse5() {
        XCTAssertEqual(Util.parseCsvLine(line: "alice, \"domain1, domain2\", \"data1, data2\", action1"), ["alice","domain1, domain2","data1, data2","action1"])
    }
    
}
