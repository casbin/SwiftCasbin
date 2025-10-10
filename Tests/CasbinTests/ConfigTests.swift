import Testing
import Casbin

@Suite("Config Tests")
struct ConfigTests {

    @Test("Load config from file")
    func testGet() async throws {
        let filePath = #filePath.components(separatedBy: "ConfigTests.swift")[0] + "examples/testini.ini"
        var config = try await Config.from(file: filePath)

        #expect(config.getBool(key: "debug") == true)
        #expect(config.getInt(key: "math::math.i64") == 64)
        #expect(config.getFloat(key: "math::math.f64") == 64.1)
        #expect(config.get(key: "mysql::mysql.master.host") == "10.0.0.1")
        config.set(key: "other::key1", value: "new test key")
        #expect(config.get(key: "other::key1") == "new test key")
        config.set(key: "other::key1", value: "test key")
        #expect(config.get(key: "other::key1") == "test key")
        #expect(config.get(key: "multi1::name") == "r.sub==p.sub&&r.obj==p.obj")
        #expect(config.get(key: "multi2::name") == "r.sub==p.sub&&r.obj==p.obj")
        #expect(config.get(key: "multi3::name") == "r.sub==p.sub&&r.obj==p.obj")
        #expect(config.get(key: "multi4::name") == "")
        #expect(config.get(key: "multi5::name") == "r.sub==p.sub&&r.obj==p.obj")
    }

    @Test("Parse config from text")
    func testFromText() async throws {
        let text = #"""
            # test config
                            debug = true
                            url = act.wiki
                            ; redis config
                            [redis]
                            redis.key = push1,push2
                            ; mysql config
                            [mysql]
                            mysql.dev.host = 127.0.0.1
                            mysql.dev.user = root
                            mysql.dev.pass = 123456
                            mysql.dev.db = test
                            mysql.master.host = 10.0.0.1
                            mysql.master.user = root
                            mysql.master.pass = 89dds)2$#d
                            mysql.master.db = act
                            ; math config
                            [math]
                            math.i64 = 64
                            math.f64 = 64.1
        """#

        var config = try await Config.from(text: text)
        #expect(config.getBool(key: "debug") == true)
        #expect(config.getInt(key: "math::math.i64") == 64)
        #expect(config.getFloat(key: "math::math.f64") == 64.1)
        #expect(config.get(key: "mysql::mysql.master.host") == "10.0.0.1")
        config.set(key: "other::key1", value: "new test key")
        #expect(config.get(key: "other::key1") == "new test key")
        config.set(key: "other::key1", value: "test key")
        #expect(config.get(key: "other::key1") == "test key")
    }
}
