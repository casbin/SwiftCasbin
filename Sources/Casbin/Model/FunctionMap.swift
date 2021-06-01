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

import Expression

public struct FunctionMap {
    public var functions:[String:ExpressionFunction] = [:]
    
    public mutating func addFuntion(name:String,function: @escaping ExpressionFunction) {
        functions[name] = function
    }
    
    public static func `default`() -> FunctionMap {
        var fm = FunctionMap.init()
        fm.addFuntion(name: "keyMatch",
                      function: Util.toExpressionFunction(name: "keyMatch", function: Util.keyMatch))
        fm.addFuntion(name: "keyMatch2",
                      function: Util.toExpressionFunction(name: "keyMatch2", function: Util.keyMatch2))
        fm.addFuntion(name: "keyMatch3",
                      function: Util.toExpressionFunction(name: "keyMatch3", function: Util.keyMatch3))
        fm.addFuntion(name: "regexMatch",
                      function: Util.toExpressionFunction(name: "regexMatch", function: Util.regexMatch))
        fm.addFuntion(name: "globMatch",
                      function: Util.toExpressionFunction(name: "globMatch", function: Util.regexMatch))
        fm.addFuntion(name: "ipMatch",
                      function: Util.toExpressionFunction(name: "ipMatch", function: Util.regexMatch))
        
        
        return fm
    }
}
