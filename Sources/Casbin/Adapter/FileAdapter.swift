// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import NIO

public typealias LoadPolicyFileHandler = @Sendable (String,Model) -> Void
public typealias LoadFilteredPolicyFileHandler = @Sendable (String,Model,Filter) -> Bool

public final class FileAdapter {
    var filePath:String
    public var isFiltered:Bool = false
    public var eventloop: EventLoop
    public var fileIo: NonBlockingFileIO
    
    public init(filePath:String,fileIo:NonBlockingFileIO,eventloop:EventLoop) {
        self.fileIo = fileIo
        self.eventloop = eventloop
        self.filePath = filePath
    }
    func load() -> EventLoopFuture<ByteBuffer> {
        fileIo.openFile(path: filePath, eventLoop: eventloop).flatMap { [self] arg -> EventLoopFuture<ByteBuffer> in
            fileIo.read(fileRegion: arg.1, allocator: .init(), eventLoop: eventloop)
                .flatMapThrowing { buffer in
                    try arg.0.close()
                    return buffer
                }
        }
    }
    
    func loadPolicyFile(m:Model,handler:@escaping LoadPolicyFileHandler) -> EventLoopFuture<Void> {
        load().map { buffer in
            let s = buffer.getString(at: 0, length: buffer.readableBytes) ?? ""
            let lines = s.split(separator: "\n")
            lines.forEach {
                handler(String($0),m)
            }
        }
    }
    func loadFilteredPolicyFile(m:Model,filter:Filter,handler: @escaping LoadFilteredPolicyFileHandler)-> EventLoopFuture<Bool> {
        load().map { buffer in
            let s = buffer.getString(at: 0, length: buffer.readableBytes) ?? ""
            let lines = s.split(separator: "\n")
            var isFiltered = false
            for line in lines {
                if handler(String(line),m,filter) {
                    isFiltered = true
                }
            }
            return isFiltered
        }
    }
    
    func savePolicyFile(text:String) -> EventLoopFuture<Void> {
        fileIo.openFile(path: filePath,
                        mode: .write,
                        flags: .allowFileCreation(),
                        eventLoop: eventloop)
            .flatMap { [self] handle in
                            fileIo.write(fileHandle: handle,
                                         buffer: .init(string: text),
                                         eventLoop: eventloop)
                            .flatMapThrowing { _ in try handle.close()}
                        }
        }
}

extension FileAdapter: Adapter {
    public func loadPolicy(m: Model) -> EventLoopFuture<Void> {
        loadPolicyFile(m: m, handler:Util.loadPolicyLine(line:m:))
    }

    public func loadFilteredPolicy(m: Model, f: Filter) -> EventLoopFuture<Void> {
        loadFilteredPolicyFile(m: m, filter: f, handler: Util.loadFilteredPolicyLine).map {
            self.isFiltered = $0
        }
    }

    public func savePolicy(m: Model) -> EventLoopFuture<Void> {
        if filePath.isEmpty {
            return eventloop.makeFailedFuture(CasbinError.IoError("save policy failed, file path is empty"))
        }
        var policies = ""
        guard let astMap = m.getModel()["p"] else {
            return eventloop.makeFailedFuture(CasbinError.MODEL_ERROR(.P("Missing policy definition in conf file")))
        }
        for (ptype,ast) in astMap {
            for rule in ast.policy {
                policies.append("\(ptype),\(rule.joined(separator: ","))\n")
            }
        }
        if let asts =  m.getModel()["g"] {
            for (ptype,ast) in asts {
                for rule in ast.policy {
                    policies.append("\(ptype),\(rule.joined(separator: ","))\n")
                }
            }
        }
        return savePolicyFile(text: policies)
    }

    public func clearPolicy() -> EventLoopFuture<Void> {
        savePolicyFile(text: "")
    }

    public func addPolicy(sec: String, ptype: String, rule: [String]) -> EventLoopFuture<Bool> {
        // this api shouldn't implement, just for convenience
        eventloop.makeSucceededFuture(true)
    }

    public func addPolicies(sec: String, ptype: String, rules: [[String]]) -> EventLoopFuture<Bool> {
        // this api shouldn't implement, just for convenience
        eventloop.makeSucceededFuture(true)
    }

    public func removePolicy(sec: String, ptype: String, rule: [String]) -> EventLoopFuture<Bool> {
        // this api shouldn't implement, just for convenience
        eventloop.makeSucceededFuture(true)
    }

    public func removePolicies(sec: String, ptype: String, rules: [[String]]) -> EventLoopFuture<Bool> {
        // this api shouldn't implement, just for convenience
        eventloop.makeSucceededFuture(true)
    }

    public func removeFilteredPolicy(sec: String, ptype: String, fieldIndex: Int, fieldValues: [String]) -> EventLoopFuture<Bool> {
        // this api shouldn't implement, just for convenience
        eventloop.makeSucceededFuture(true)
    }


}
