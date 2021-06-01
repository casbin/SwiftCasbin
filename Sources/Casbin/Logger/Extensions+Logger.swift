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

import Logging

extension Logger {
    func printEnforceLog(rvals:[String],cached:Bool,authorized:Bool,level: Level = .info) {
        log(level: level, "Enforce Request:Request -> \(rvals.joined(separator: ",")),Cached -> \(cached),Response -> \(authorized)")
    }
    
    func printMgmtLog(e:EventData,level: Level = .info) {
        log(level: level, "Policy Management: Event -> \(e.description)")
    }
    
    func printExplainLog(rules:[String],level: Level = .info) {
        log(level: level, "Hitted Policies: Explain -> \(rules.joined(separator: ","))")
    }
    func printStatusLog(enabled:Bool,level: Level = .info) {
        log(level: level, "Status:Enabled -> \(enabled)")
    }
}
