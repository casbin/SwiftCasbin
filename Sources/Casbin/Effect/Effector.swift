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

public protocol EffectorStream {
    func next() -> Bool
    func explain() -> [Int]?
    mutating func pushEffect(eft:Effect) -> Bool
}
public protocol Effector {
    func newStream(expr:String,cap:Int) -> EffectorStream
}


public struct DefaultEffectStream {
    var done:Bool
    var res: Bool
    var expr: String
    var idx: Int
    var cap: Int
    var expl:[Int]
}

extension DefaultEffectStream : EffectorStream {
    public func next() -> Bool {
        assert(self.done)
        return self.res
    }
    
    public func explain() -> [Int]? {
        assert(self.done)
        if self.expl.isEmpty {
            return nil
        } else {
           return self.expl
        }
    }
    
    public mutating func pushEffect(eft: Effect) -> Bool {
        if self.expr == "some(where (p_eft == allow))" {
            if eft == .Allow {
                self.done = true
                self.res = true
                pushIndex()
            }
            
        } else if expr == "some(where (p_eft == allow)) && !some(where (p_eft == deny))" {
            if eft == .Allow {
                res = true
                pushIndex()
            } else if eft == .Deny {
                done = true
                res = false
                pushIndex()
            }
        } else if expr == "!some(where (p_eft == deny))" {
            if eft == .Deny {
                done = true
                res = false
                pushIndex()
            }
        } else if expr == "priority(p_eft) || deny"
                    && eft != .Indeterminate {
            if eft == .Allow {
                res = true
            } else {
                res = false
            }
            done = true
        }
        
        if idx + 1 == cap {
            done = true
            idx = cap
        } else {
            idx += 1
        }
        return done
    }
    
    mutating func pushIndex() {
        if cap > 1 {
            expl.append(idx)
        }
    }
}


public struct DefaultEffector: Effector {
    public func newStream(expr: String, cap: Int) -> EffectorStream {
        // Avoid crashing on empty policy sets; treat as no-allow.
        if cap <= 0 {
            return DefaultEffectStream(done: true, res: false, expr: expr, idx: 0, cap: 0, expl: [])
        }
        
        var res:Bool {
            switch expr {
            case "some(where (p_eft == allow))",
                 "some(where (p_eft == allow)) && !some(where (p_eft == deny))",
                 "priority(p_eft) || deny":
                return false
            case "!some(where (p_eft == deny))":
                return true
            default:
                preconditionFailure("unsupported effect:\(expr)")
            }
        }
        return DefaultEffectStream.init(done: false, res: res, expr: expr, idx: 0, cap: cap, expl: [])
    }
    
    
}
