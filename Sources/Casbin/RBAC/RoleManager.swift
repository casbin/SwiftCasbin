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

import Foundation

public protocol RoleManager {
    
    /// clears all stored data and resets the role manager to the initial state.
    mutating func clear()
    
    /// adds the inheritance link between two roles
    /// - Parameters:
    ///   - name1: role
    ///   - name2: role
    ///   - domain:a prefix to the roles.
    mutating func addLink(name1: String,name2: String,domain: String?)
    
    /// deletes the inheritance link between two roles.
    /// - Parameters:
    ///   - name1: role
    ///   - name2: role
    ///   - domain: a prefix to the roles.
    mutating func deleteLink(name1: String,name2: String,domain: String?) -> CasbinResult<Void>
    
    
    /// determines whether a link exists between two roles.
    /// - Parameters:
    ///   - name1: the first role (or a user).
    ///   - name2: the second role
    ///   - domain: the domain the roles belong to
    /// - returns:  whether name1 inherits name2 (name1 has role name2).
    func hasLink(name1: String,name2: String,domain: String?) -> Bool
    
    /// gets the roles that a user inherits
    /// - Parameters:
    ///   - name: the user (or a role).
    ///   - domain: the domain the roles belong to.
    /// - returns:the roles
    func getRoles(name:String,domain: String?) -> [String]
    /// gets the users that inherits a role.
    /// - Parameters:
    ///   - name: the role
    ///   - domain: a prefix to the users (can be used for other purposes)
    /// - returns:the users
    func getUsers(name:String,domain: String?) -> [String]
    

    
}
