import Testing
import Casbin

@Suite("Utilities: CSV + assertion escaping", .timeLimit(.minutes(1)))
struct UtilsTests {
    @Test("escapeAssertion replaces dots with underscores")
    func testEscapeAssertion() {
        let s = "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act"
        let exp = "g(r_sub, p_sub) && r_obj == p_obj && r_act == p_act"
        #expect(Util.escapeAssertion(s) == exp)

        let s1 = "g(r2.sub, p2.sub) && r2.obj == p2.obj && r2.act == p2.act"
        let exp1 = "g(r2_sub, p2_sub) && r2_obj == p2_obj && r2_act == p2_act"
        #expect(Util.escapeAssertion(s1) == exp1)
    }

    @Test("CSV parsing: simple")
    func testCsvParse1() {
        #expect(Util.parseCsvLine(line: "alice, domain1, data1, action1") == ["alice","domain1","data1","action1"])
    }

    @Test("CSV parsing: quoted field with comma")
    func testCsvParse2() {
        #expect(Util.parseCsvLine(line: #"alice, "domain1, domain2", data1 , action1"#) == ["alice","domain1, domain2","data1","action1"])
    }

    @Test("CSV parsing: only comma yields nil")
    func testCsvParse3() {
        #expect(Util.parseCsvLine(line: ",") == nil)
    }

    @Test("CSV parsing: edge cases")
    func testCsvParse4() {
        #expect(Util.parseCsvLine(line: "") == nil)
        #expect(Util.parseCsvLine(line: "#") == nil)
        #expect(Util.parseCsvLine(line: " #") == nil)
        #expect(Util.parseCsvLine(line: "\" ") == ["\""])
        #expect(Util.parseCsvLine(line: "\" alice") == ["\" alice"])
        #expect(Util.parseCsvLine(line: "alice, \"domain1, domain2") == ["alice","\"domain1, domain2"])
        #expect(Util.parseCsvLine(line: "\"\"") == [""])
        #expect(Util.parseCsvLine(line: "r.sub.Status == \"ACTIVE\", /data1, read") == ["r.sub.Status == \"ACTIVE\"","/data1","read"])
    }

    @Test("CSV parsing: multiple quoted fields")
    func testCsvParse5() {
        #expect(Util.parseCsvLine(line: "alice, \"domain1, domain2\", \"data1, data2\", action1") == ["alice","domain1, domain2","data1, data2","action1"])
    }
}
