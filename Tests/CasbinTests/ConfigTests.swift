import Testing
import Casbin
import NIO

@Suite("Config parsing", .timeLimit(.minutes(1)))
struct ConfigTests {
    @Test("load from file and get/set")
    func testGet() throws {
        let filePath = #file.components(separatedBy: "ConfigTests.swift")[0] + "examples/testini.ini"
        let pool = NIOThreadPool(numberOfThreads: 1)
        pool.start()
        defer { shutdownThreadPoolInBackground(pool) }
        let elg = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { shutdownEventLoopGroupInBackground(elg) }
        let fileIo = NonBlockingFileIO(threadPool: pool)

        var config = try Config.from(file: filePath, fileIo: fileIo, on: elg.next()).wait()

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

    @Test("load from text and get/set")
    func testFromText() throws {
        let elg = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { shutdownEventLoopGroupInBackground(elg) }
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

        var config = try Config.from(text: text, on: elg.next()).wait()
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
