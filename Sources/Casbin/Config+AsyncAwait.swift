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

@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
extension Config {

    // Generic bridge from EventLoopFuture to async/await
    private static func awaitFuture<T>(_ future: EventLoopFuture<T>) async throws -> T {
        try await withCheckedThrowingContinuation { cont in
            future.whenComplete { result in
                cont.resume(with: result)
            }
        }
    }

    /// Load configuration from a file asynchronously
    public static func from(file: String, fileIo: NonBlockingFileIO, on eventloop: EventLoop) async throws -> Config {
        let future: EventLoopFuture<Config> = Config.from(file: file, fileIo: fileIo, on: eventloop)
        return try await awaitFuture(future)
    }

    /// Load configuration from text asynchronously
    public static func from(text: String, on eventloop: EventLoop) async throws -> Config {
        let future: EventLoopFuture<Config> = Config.from(text: text, on: eventloop)
        return try await awaitFuture(future)
    }
}
