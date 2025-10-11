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

public struct Config: Sendable {
    var data: [String:[String:String]] = [:]
    static let DEFAULT_SECTION = "default"
    static let DEFAULT_COMMENT:Character = "#"
    static let DEFAULT_COMMENT_SEM:Character = ";"
    static let DEFAULT_MULTI_LINE_SEPARATOR:Character = "\\"
    var eventLoop:EventLoop

    public static func from(file:String,fileIo:NonBlockingFileIO,on eventloop:EventLoop) -> EventLoopFuture<Self> {
        fileIo.openFile(path: file, eventLoop: eventloop).flatMap { arg -> EventLoopFuture<ByteBuffer> in
            fileIo.read(fileRegion: arg.1, allocator: .init(), eventLoop: eventloop)
                .flatMapThrowing { buffer in
                    try arg.0.close()
                    return buffer
                }
        }.flatMap { buffer in
            let s = buffer.getString(at: 0, length: buffer.readableBytes) ?? ""
            var config = Config.init(eventLoop: eventloop)
            switch config.parse(s) {
            case .success:
                return eventloop.makeSucceededFuture(config)
            case .failure(let e) :
                return eventloop.makeFailedFuture(e)
            }
        }
    }
    public static func from(text:String,on eventloop:EventLoop) -> EventLoopFuture<Self> {
        var config = Config.init(eventLoop: eventloop)
        switch config.parse(text) {
        case .success:
            return eventloop.makeSucceededFuture(config)
        case .failure(let e) :
            return eventloop.makeFailedFuture(e)
        }
    }
    private mutating func parse(_ s: String) -> CasbinResult<Void> {
        let s = s.replacingOccurrences(of: "\r", with: "")
        let lines = s.split(separator: "\n")
        let linesCount = lines.count
        var section = ""
        var currentLine = ""
        for (index,value) in lines.enumerated() {
            var line = String(value)
             if let commentPos =  line.firstIndex(of: Self.DEFAULT_COMMENT) {
                line = String(line[..<commentPos])
            }
            if let commentPos =  line.firstIndex(of: Self.DEFAULT_COMMENT_SEM) {
               line = String(line[..<commentPos])
           }
            line = line.trimmingCharacters(in: .whitespaces)
            if line.isEmpty {
                continue
            }
            let lineNumber = index + 1
            if line.hasPrefix("[") && line.hasSuffix("]") {
                if currentLine.count != 0 {
                    if case let .failure(e) = write(sec: section, lineNum: lineNumber - 1, line: currentLine) {
                        return .failure(e)
                    }
                    currentLine = ""
                }
                
                section = String(line[line.index(after: line.startIndex)..<line.index(before: line.endIndex)])
            } else {
                var shouldWrite = false
                if line.contains(Self.DEFAULT_MULTI_LINE_SEPARATOR) {
                    currentLine += line[..<line.index(before: line.endIndex)].trimmingCharacters(in: .whitespaces)
                } else {
                    currentLine += line
                    shouldWrite = true
                }
                if shouldWrite || lineNumber == linesCount {
                    if case let .failure(e) = write(sec: section, lineNum: lineNumber, line: currentLine) {
                        return .failure(e)
                    }
                    currentLine = ""
                }
            }
            
        }
        return .success(())
    }
    private mutating func write(sec:String,lineNum:Int,line:String)-> CasbinResult<Void> {
        guard let equalIndex = line.firstIndex(of: "=") else {
            return .failure(CasbinError.IoError("parse the content error : line \(lineNum)"))
        }
        let key = line[..<equalIndex].trimmingCharacters(in: .whitespaces)
        let value = line[line.index(after: equalIndex)...].trimmingCharacters(in: .whitespaces)
        addConfig(section: sec, option: key, value: value)
        return .success(())
    }
    public mutating func addConfig(section:String,option:String,value:String) {
        var sec = section
        if section.isEmpty {
            sec = Self.DEFAULT_SECTION
        }
        var sectionValue = data.getOrInsert(key: sec, with: [:])
        sectionValue.updateValue(value, forKey: option)
        data.updateValue(sectionValue, forKey: sec)
    }
    public func get(key:String) -> String {
        let keys = key.lowercased().components(separatedBy: "::")
        if keys.count >= 2 {
            let sec = keys[0]
            let option = keys[1]
            return data[sec]?[option] ?? ""
        } else {
            let sec = Self.DEFAULT_SECTION
            let option = keys[0]
            return data[sec]?[option] ?? ""
        }
    }
    public mutating func set(key:String,value:String) {
        if key.isEmpty {
            preconditionFailure("key can't be empty")
        }
        let keys = key.lowercased().components(separatedBy: "::")
        if keys.count >= 2 {
            let sec = keys[0]
            let option = keys[1]
            addConfig(section: sec, option: option, value: value)
        } else {
            let sec = Self.DEFAULT_SECTION
            let option = keys[0]
            addConfig(section: sec, option: option, value: value)
        }
    }
}

public extension Config {
    func getBool(key:String) -> Bool? {
        Bool(get(key: key))
    }
    func getInt(key:String) -> Int? {
        Int(get(key: key))
    }
    func getFloat(key:String) -> Double? {
        Double(get(key: key))
    }
    func getStrings(key:String) -> [String] {
      get(key: key).split(separator: ",").map { String($0) }
    }
}
