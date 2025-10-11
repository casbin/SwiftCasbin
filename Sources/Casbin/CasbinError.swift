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
public enum CasbinError: Error, LocalizedError, CustomStringConvertible, Sendable {
    public var description: String {
        switch self {
        case .RBAC_ERROR(let e):
            return "RBAC Error:\(e.description)"
            
        case .MATCH_ERROR(let e):
            return "Match error: \(e.description)"
        case .MODEL_ERROR(let e):
            return "Model error: \(e.description)"
        case .OtherErrorMessage(let s):
            return "casbin error: \(s)"
        
        case .IoError(let s):
            return s
        }
    }
    case RBAC_ERROR(RbacError)
    case MATCH_ERROR(MatchError)
    case MODEL_ERROR(ModelError)
    case OtherErrorMessage(String)
    case IoError(String)
    
    public enum MatchError: CustomStringConvertible, Sendable {
        public var description: String {
            switch self {
           
            case .MatchFuntionArgsCountError(let count):
                return "Expected 2 arguments, but got \(count)"
            case .MatchFuntionArgsNotString:
                return "Argument must be a string"
            }
        }
        
        case MatchFuntionArgsCountError(Int)
        case MatchFuntionArgsNotString
    }
     
    public enum RbacError: CustomStringConvertible, Sendable {
        public var description: String {
            switch self {
            
            case .NameNotFound:
                return "name does not exist"
            case .DomainParameter:
                return "domain should be 1 parameter"
            case .NamesNotFound:
                return "name1 or name2 does not exist"
            case .UserDomainParameter:
                return "useDomain should be 1 parameter"
            case .InvalidFieldVaulesParameter:
                return "fieldValues requires at least one parameter"
            }
        }
        
        case NameNotFound
        case DomainParameter
        case NamesNotFound
        case UserDomainParameter
        case InvalidFieldVaulesParameter
    }
    
    public enum ModelError: CustomStringConvertible, Sendable {
        public var description: String {
            switch self {
           
            case .R(let s):
                return "Invalid request definition:\(s)"
            case .P(let s):
                return "Invalid policy definition:\(s)"
            case .E(let s):
                return "Unsupported effect:\(s)"
            case .M(let s):
                return "Invalid matcher:\(s)"
            case .Other(let s):
                return "Other:\(s)"
            }
        }
        
        case R(String)
        case P(String)
        case E(String)
        case M(String)
        case Other(String)
    }
}
