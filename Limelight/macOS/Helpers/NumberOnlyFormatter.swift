//
//  NumberOnlyFormatter.swift
//  Moonlight for macOS
//
//  Created by Michael Kenny on 20/6/2024.
//  Copyright © 2024 Moonlight Game Streaming Project. All rights reserved.
//

import Foundation

class NumberOnlyFormatter: Formatter {    
    override func string(for obj: Any?) -> String? {
        // Convert the number to a string
        if let number = obj as? NSNumber {
            return number.stringValue
        }
        return nil
    }
    
    override func getObjectValue(_ obj: AutoreleasingUnsafeMutablePointer<AnyObject?>?, for string: String, errorDescription error: AutoreleasingUnsafeMutablePointer<NSString?>?) -> Bool {
        // Check if the string can be converted to a valid number
        if string.isEmpty {
            return true
        } else {
            if let number = Double(string) {
                obj?.pointee = NSNumber(value: number)
                return true
            } else {
                // If conversion fails, set an error description
                if error != nil {
                    error?.pointee = "Input is not a valid number" as NSString
                }
                return false
            }
        }
    }
    
    override func isPartialStringValid(_ partialString: String, newEditingString: AutoreleasingUnsafeMutablePointer<NSString?>?, errorDescription: AutoreleasingUnsafeMutablePointer<NSString?>?) -> Bool {
        // Validate input, only allow numbers and optional dot
        let numberCharacterSet = CharacterSet(charactersIn: "0123456789.")
        guard partialString.rangeOfCharacter(from: numberCharacterSet.inverted) == nil else {
            return false
        }

        // 限制输入长度：这些输入框后续会做 Double -> Int 转换，
        // 超长数值（例如 99999999999999999999）会直接让转换触发运行时 trap。
        guard partialString.count <= Self.maximumInputLength else {
            errorDescription?.pointee = "Input is too long" as NSString
            return false
        }

        return true
    }

    /// 允许输入的最大字符数，足以覆盖分辨率、帧率、码率等所有合法取值
    private static let maximumInputLength = 10
}
