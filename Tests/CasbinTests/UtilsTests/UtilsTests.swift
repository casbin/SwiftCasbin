import Testing
import Casbin

@Suite("Utils Tests")
struct UtilsTests {
    @Test("escapeAssertion")
    func testEscapeAssertion() {
        let s = "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act"
        let exp = "g(r_sub, p_sub) && r_obj == p_obj && r_act == p_act"
        #expect(exp == Util.escapeAssertion(s))
        
        let s1 = "g(r2.sub, p2.sub) && r2.obj == p2.obj && r2.act == p2.act"
        let exp1 = "g(r2_sub, p2_sub) && r2_obj == p2_obj && r2_act == p2_act"
        #expect(exp1 == Util.escapeAssertion(s1))
    }
    @Test("csvParse1")
    func testCsvParse1() {
        #expect(Util.parseCsvLine(line: "alice, domain1, data1, action1") == ["alice","domain1","data1","action1"])
    }
    @Test("csvParse2")
    func testCsvParse2() {
        #expect(Util.parseCsvLine(line: #"alice, "domain1, domain2", data1 , action1"#) == ["alice","domain1, domain2","data1","action1"])
    }
    @Test("csvParse3")
    func testCsvParse3() {
        #expect(Util.parseCsvLine(line: ",") == nil)
    }
    @Test("csvParse4")
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
    @Test("csvParse5")
    func testCsvParse5() {
        #expect(Util.parseCsvLine(line: "alice, \"domain1, domain2\", \"data1, data2\", action1") == ["alice","domain1, domain2","data1, data2","action1"])
    }
    
   
 
}
