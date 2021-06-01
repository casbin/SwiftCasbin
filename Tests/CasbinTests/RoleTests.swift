
import XCTest
import Casbin
final class RoleTests: XCTestCase {
    struct Params {
        let name1: String
        let name2: String
    }
    func testRole() {
        let rm = DefaultRoleManager.init(maxHierarchyLevel: 3)
        
        let params:[Params] = [.init(name1: "u1", name2: "g1"),
                               .init(name1: "u2", name2: "g1"),
                               .init(name1: "u3", name2: "g2"),
                               .init(name1: "u4", name2: "g2"),
                               .init(name1: "u4", name2: "g3"),
                               .init(name1: "g1", name2: "g3")]
        params.forEach { p in
            rm.addLink(name1: p.name1, name2: p.name2, domain: nil)
        }
        params.forEach { p in
            XCTAssertTrue(rm.hasLink(name1: p.name1, name2: p.name2, domain: nil))
        }
        XCTAssertFalse(rm.hasLink(name1: "u1", name2: "g2", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u2", name2: "g2", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u3", name2: "g1", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u3", name2: "g3", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u4", name2: "g1", domain: nil))
        
        // test getROles
        
        XCTAssertEqual(["g1"], rm.getRoles(name: "u1", domain: nil))
        XCTAssertEqual(["g1"], rm.getRoles(name: "u2", domain: nil))
        XCTAssertEqual(["g2"], rm.getRoles(name: "u3", domain: nil))
        XCTAssertEqual(["g2","g3"], rm.getRoles(name: "u4", domain: nil).sorted())
        XCTAssertEqual(["g3"], rm.getRoles(name: "g1", domain: nil))
        XCTAssertEqual([], rm.getRoles(name: "g2", domain: nil))
        XCTAssertEqual([], rm.getRoles(name: "g3", domain: nil))
        
        // test deleteLink
        _ = rm.deleteLink(name1: "g1", name2: "g3", domain: nil)
        _ = rm.deleteLink(name1: "u4", name2: "g2", domain: nil)
        
        XCTAssertTrue(rm.hasLink(name1: "u1", name2: "g1", domain: nil))
        XCTAssertTrue(rm.hasLink(name1: "u2", name2: "g1", domain: nil))
        XCTAssertTrue(rm.hasLink(name1: "u3", name2: "g2", domain: nil))
        XCTAssertTrue(rm.hasLink(name1: "u4", name2: "g3", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u1", name2: "g2", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u1", name2: "g3", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u2", name2: "g2", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u2", name2: "g3", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u3", name2: "g1", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u3", name2: "g3", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u4", name2: "g1", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u4", name2: "g2", domain: nil))
        XCTAssertEqual(["g1"], rm.getRoles(name: "u1", domain: nil))
        XCTAssertEqual(["g1"], rm.getRoles(name: "u2", domain: nil))
        XCTAssertEqual(["g2"], rm.getRoles(name: "u3", domain: nil))
        XCTAssertEqual(["g3"], rm.getRoles(name: "u4", domain: nil))
        XCTAssertEqual([], rm.getRoles(name: "g1", domain: nil))
        XCTAssertEqual([], rm.getRoles(name: "g2", domain: nil))
        XCTAssertEqual([], rm.getRoles(name: "g3", domain: nil))
        
    }
    
    func testClear() {
        let rm = DefaultRoleManager.init(maxHierarchyLevel: 3)
        
        let params:[Params] = [.init(name1: "u1", name2: "g1"),
                               .init(name1: "u2", name2: "g1"),
                               .init(name1: "u3", name2: "g2"),
                               .init(name1: "u4", name2: "g2"),
                               .init(name1: "u4", name2: "g3"),
                               .init(name1: "g1", name2: "g3")]
        params.forEach { p in
            rm.addLink(name1: p.name1, name2: p.name2, domain: nil)
        }
        rm.clear()
        XCTAssertFalse(rm.hasLink(name1: "u1", name2: "g1", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u1", name2: "g2", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u1", name2: "g3", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u2", name2: "g1", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u2", name2: "g2", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u2", name2: "g3", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u3", name2: "g1", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u3", name2: "g2", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u3", name2: "g3", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u4", name2: "g1", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u4", name2: "g2", domain: nil))
        XCTAssertFalse(rm.hasLink(name1: "u4", name2: "g3", domain: nil))
    }
    
    func testDomainRole() {
        let rm = DefaultRoleManager.init(maxHierarchyLevel: 3)
        rm.addLink(name1: "u1", name2: "g1", domain: "domain1")
        rm.addLink(name1: "u2", name2: "g1", domain: "domain1")
        rm.addLink(name1: "u3", name2: "admin", domain: "domain2")
        rm.addLink(name1: "u4", name2: "admin", domain: "domain2")
        rm.addLink(name1: "u4", name2: "admin", domain: "domain1")
        rm.addLink(name1: "g1", name2: "admin", domain: "domain1")
        
        XCTAssertEqual(true, rm.hasLink(name1: "u1", name2: "g1", domain: "domain1"))
        XCTAssertEqual(false, rm.hasLink(name1: "u1", name2: "g1", domain: "domain2"))
        XCTAssertEqual(true, rm.hasLink(name1: "u1", name2: "admin", domain: "domain1"))
        XCTAssertEqual(false, rm.hasLink(name1: "u1", name2: "admin", domain: "domain2"))
        
        XCTAssertEqual(true, rm.hasLink(name1: "u2", name2: "g1", domain: "domain1"))
        XCTAssertEqual(false, rm.hasLink(name1: "u2", name2: "g1", domain: "domain2"))
        XCTAssertEqual(true, rm.hasLink(name1: "u2", name2: "admin", domain: "domain1"))
        XCTAssertEqual(false, rm.hasLink(name1: "u2", name2: "admin", domain: "domain2"))
        
        XCTAssertEqual(false, rm.hasLink(name1: "u3", name2: "g1", domain: "domain1"))
        XCTAssertEqual(false, rm.hasLink(name1: "u3", name2: "g1", domain: "domain2"))
        XCTAssertEqual(false, rm.hasLink(name1: "u3", name2: "admin", domain: "domain1"))
        XCTAssertEqual(true, rm.hasLink(name1: "u3", name2: "admin", domain: "domain2"))
        
        XCTAssertEqual(false, rm.hasLink(name1: "u4", name2: "g1", domain: "domain1"))
        XCTAssertEqual(false, rm.hasLink(name1: "u4", name2: "g1", domain: "domain2"))
        XCTAssertEqual(true, rm.hasLink(name1: "u4", name2: "admin", domain: "domain1"))
        XCTAssertEqual(true, rm.hasLink(name1: "u4", name2: "admin", domain: "domain2"))
        
       _ = rm.deleteLink(name1: "g1", name2: "admin", domain: "domain1")
       _ = rm.deleteLink(name1: "u4", name2: "admin", domain: "domain2")
        
        XCTAssertEqual(true, rm.hasLink(name1: "u1", name2: "g1", domain: "domain1"))
        XCTAssertEqual(false, rm.hasLink(name1: "u1", name2: "g1", domain: "domain2"))
        XCTAssertEqual(false, rm.hasLink(name1: "u1", name2: "admin", domain: "domain1"))
        XCTAssertEqual(false, rm.hasLink(name1: "u1", name2: "admin", domain: "domain2"))
        
        XCTAssertEqual(true, rm.hasLink(name1: "u2", name2: "g1", domain: "domain1"))
        XCTAssertEqual(false, rm.hasLink(name1: "u2", name2: "g1", domain: "domain2"))
        XCTAssertEqual(false, rm.hasLink(name1: "u2", name2: "admin", domain: "domain1"))
        XCTAssertEqual(false, rm.hasLink(name1: "u2", name2: "admin", domain: "domain2"))
        
        XCTAssertEqual(false, rm.hasLink(name1: "u3", name2: "g1", domain: "domain1"))
        XCTAssertEqual(false, rm.hasLink(name1: "u3", name2: "g1", domain: "domain2"))
        XCTAssertEqual(false, rm.hasLink(name1: "u3", name2: "admin", domain: "domain1"))
        XCTAssertEqual(true, rm.hasLink(name1: "u3", name2: "admin", domain: "domain2"))
        
        XCTAssertEqual(false, rm.hasLink(name1: "u4", name2: "g1", domain: "domain1"))
        XCTAssertEqual(false, rm.hasLink(name1: "u4", name2: "g1", domain: "domain2"))
        XCTAssertEqual(true, rm.hasLink(name1: "u4", name2: "admin", domain: "domain1"))
        XCTAssertEqual(false, rm.hasLink(name1: "u4", name2: "admin", domain: "domain2"))
    }
    
    func testUsers() {
        let rm = DefaultRoleManager.init(maxHierarchyLevel: 3)
        rm.addLink(name1: "u1", name2: "g1", domain: "domain1")
        rm.addLink(name1: "u2", name2: "g1", domain: "domain1")
        rm.addLink(name1: "u3", name2: "g2", domain: "domain2")
        rm.addLink(name1: "u4", name2: "g2", domain: "domain2")
        rm.addLink(name1: "u5", name2: "g3", domain: nil)
        
        XCTAssertEqual(["u1","u2"], rm.getUsers(name: "g1", domain: "domain1").sorted())
        XCTAssertEqual(["u3","u4"], rm.getUsers(name: "g2", domain: "domain2").sorted())
        XCTAssertEqual(["u5"], rm.getUsers(name: "g3", domain: nil))
    }
   
}
