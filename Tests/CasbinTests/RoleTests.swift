import Testing
import Casbin
@Suite("Role Manager Tests")
struct RoleTests {
    struct Params {
        let name1: String
        let name2: String
    }
    @Test("Role hierarchy management")
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
            #expect(rm.hasLink(name1: p.name1, name2: p.name2, domain: nil))
        }
        #expect(!rm.hasLink(name1: "u1", name2: "g2", domain: nil))
        #expect(!rm.hasLink(name1: "u2", name2: "g2", domain: nil))
        #expect(!rm.hasLink(name1: "u3", name2: "g1", domain: nil))
        #expect(!rm.hasLink(name1: "u3", name2: "g3", domain: nil))
        #expect(!rm.hasLink(name1: "u4", name2: "g1", domain: nil))
        
        // test getROles
        
        #expect(["g1"] == rm.getRoles(name: "u1", domain: nil))
        #expect(["g1"] == rm.getRoles(name: "u2", domain: nil))
        #expect(["g2"] == rm.getRoles(name: "u3", domain: nil))
        #expect(["g2","g3"] == rm.getRoles(name: "u4", domain: nil).sorted())
        #expect(["g3"] == rm.getRoles(name: "g1", domain: nil))
        #expect([] == rm.getRoles(name: "g2", domain: nil))
        #expect([] == rm.getRoles(name: "g3", domain: nil))
        
        // test deleteLink
        _ = rm.deleteLink(name1: "g1", name2: "g3", domain: nil)
        _ = rm.deleteLink(name1: "u4", name2: "g2", domain: nil)
        
        #expect(rm.hasLink(name1: "u1", name2: "g1", domain: nil))
        #expect(rm.hasLink(name1: "u2", name2: "g1", domain: nil))
        #expect(rm.hasLink(name1: "u3", name2: "g2", domain: nil))
        #expect(rm.hasLink(name1: "u4", name2: "g3", domain: nil))
        #expect(!rm.hasLink(name1: "u1", name2: "g2", domain: nil))
        #expect(!rm.hasLink(name1: "u1", name2: "g3", domain: nil))
        #expect(!rm.hasLink(name1: "u2", name2: "g2", domain: nil))
        #expect(!rm.hasLink(name1: "u2", name2: "g3", domain: nil))
        #expect(!rm.hasLink(name1: "u3", name2: "g1", domain: nil))
        #expect(!rm.hasLink(name1: "u3", name2: "g3", domain: nil))
        #expect(!rm.hasLink(name1: "u4", name2: "g1", domain: nil))
        #expect(!rm.hasLink(name1: "u4", name2: "g2", domain: nil))
        #expect(["g1"] == rm.getRoles(name: "u1", domain: nil))
        #expect(["g1"] == rm.getRoles(name: "u2", domain: nil))
        #expect(["g2"] == rm.getRoles(name: "u3", domain: nil))
        #expect(["g3"] == rm.getRoles(name: "u4", domain: nil))
        #expect([] == rm.getRoles(name: "g1", domain: nil))
        #expect([] == rm.getRoles(name: "g2", domain: nil))
        #expect([] == rm.getRoles(name: "g3", domain: nil))
        
    }
    
    @Test("Clear all roles")
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
        #expect(!rm.hasLink(name1: "u1", name2: "g1", domain: nil))
        #expect(!rm.hasLink(name1: "u1", name2: "g2", domain: nil))
        #expect(!rm.hasLink(name1: "u1", name2: "g3", domain: nil))
        #expect(!rm.hasLink(name1: "u2", name2: "g1", domain: nil))
        #expect(!rm.hasLink(name1: "u2", name2: "g2", domain: nil))
        #expect(!rm.hasLink(name1: "u2", name2: "g3", domain: nil))
        #expect(!rm.hasLink(name1: "u3", name2: "g1", domain: nil))
        #expect(!rm.hasLink(name1: "u3", name2: "g2", domain: nil))
        #expect(!rm.hasLink(name1: "u3", name2: "g3", domain: nil))
        #expect(!rm.hasLink(name1: "u4", name2: "g1", domain: nil))
        #expect(!rm.hasLink(name1: "u4", name2: "g2", domain: nil))
        #expect(!rm.hasLink(name1: "u4", name2: "g3", domain: nil))
    }
    
    @Test("Domain-specific roles")
    func testDomainRole() {
        let rm = DefaultRoleManager.init(maxHierarchyLevel: 3)
        rm.addLink(name1: "u1", name2: "g1", domain: "domain1")
        rm.addLink(name1: "u2", name2: "g1", domain: "domain1")
        rm.addLink(name1: "u3", name2: "admin", domain: "domain2")
        rm.addLink(name1: "u4", name2: "admin", domain: "domain2")
        rm.addLink(name1: "u4", name2: "admin", domain: "domain1")
        rm.addLink(name1: "g1", name2: "admin", domain: "domain1")
        
        #expect(rm.hasLink(name1: "u1", name2: "g1", domain: "domain1"))
        #expect(!rm.hasLink(name1: "u1", name2: "g1", domain: "domain2"))
        #expect(rm.hasLink(name1: "u1", name2: "admin", domain: "domain1"))
        #expect(!rm.hasLink(name1: "u1", name2: "admin", domain: "domain2"))
        
        #expect(rm.hasLink(name1: "u2", name2: "g1", domain: "domain1"))
        #expect(!rm.hasLink(name1: "u2", name2: "g1", domain: "domain2"))
        #expect(rm.hasLink(name1: "u2", name2: "admin", domain: "domain1"))
        #expect(!rm.hasLink(name1: "u2", name2: "admin", domain: "domain2"))
        
        #expect(!rm.hasLink(name1: "u3", name2: "g1", domain: "domain1"))
        #expect(!rm.hasLink(name1: "u3", name2: "g1", domain: "domain2"))
        #expect(!rm.hasLink(name1: "u3", name2: "admin", domain: "domain1"))
        #expect(rm.hasLink(name1: "u3", name2: "admin", domain: "domain2"))
        
        #expect(!rm.hasLink(name1: "u4", name2: "g1", domain: "domain1"))
        #expect(!rm.hasLink(name1: "u4", name2: "g1", domain: "domain2"))
        #expect(rm.hasLink(name1: "u4", name2: "admin", domain: "domain1"))
        #expect(rm.hasLink(name1: "u4", name2: "admin", domain: "domain2"))
        
       _ = rm.deleteLink(name1: "g1", name2: "admin", domain: "domain1")
       _ = rm.deleteLink(name1: "u4", name2: "admin", domain: "domain2")
        
        #expect(rm.hasLink(name1: "u1", name2: "g1", domain: "domain1"))
        #expect(!rm.hasLink(name1: "u1", name2: "g1", domain: "domain2"))
        #expect(!rm.hasLink(name1: "u1", name2: "admin", domain: "domain1"))
        #expect(!rm.hasLink(name1: "u1", name2: "admin", domain: "domain2"))
        
        #expect(rm.hasLink(name1: "u2", name2: "g1", domain: "domain1"))
        #expect(!rm.hasLink(name1: "u2", name2: "g1", domain: "domain2"))
        #expect(!rm.hasLink(name1: "u2", name2: "admin", domain: "domain1"))
        #expect(!rm.hasLink(name1: "u2", name2: "admin", domain: "domain2"))
        
        #expect(!rm.hasLink(name1: "u3", name2: "g1", domain: "domain1"))
        #expect(!rm.hasLink(name1: "u3", name2: "g1", domain: "domain2"))
        #expect(!rm.hasLink(name1: "u3", name2: "admin", domain: "domain1"))
        #expect(rm.hasLink(name1: "u3", name2: "admin", domain: "domain2"))
        
        #expect(!rm.hasLink(name1: "u4", name2: "g1", domain: "domain1"))
        #expect(!rm.hasLink(name1: "u4", name2: "g1", domain: "domain2"))
        #expect(rm.hasLink(name1: "u4", name2: "admin", domain: "domain1"))
        #expect(!rm.hasLink(name1: "u4", name2: "admin", domain: "domain2"))
    }
    
    @Test("Get users for a role")
    func testUsers() {
        let rm = DefaultRoleManager.init(maxHierarchyLevel: 3)
        rm.addLink(name1: "u1", name2: "g1", domain: "domain1")
        rm.addLink(name1: "u2", name2: "g1", domain: "domain1")
        rm.addLink(name1: "u3", name2: "g2", domain: "domain2")
        rm.addLink(name1: "u4", name2: "g2", domain: "domain2")
        rm.addLink(name1: "u5", name2: "g3", domain: nil)
        
        #expect(["u1","u2"] == rm.getUsers(name: "g1", domain: "domain1").sorted())
        #expect(["u3","u4"] == rm.getUsers(name: "g2", domain: "domain2").sorted())
        #expect(["u5"] == rm.getUsers(name: "g3", domain: nil))
    }
   
}
