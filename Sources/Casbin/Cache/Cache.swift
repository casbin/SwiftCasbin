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

public protocol Cache:AnyObject {
    
    func setCapacity(_ c: Int)
    
    func get<K,V>(key:K,as type: V.Type) -> V? where K:Hashable&Equatable
    
    func set<K,V>(key:K,value:V) where K:Hashable&Equatable
    
    func has<K>(k:K) -> Bool where K:Hashable&Equatable
    
    func clear()
    
}
