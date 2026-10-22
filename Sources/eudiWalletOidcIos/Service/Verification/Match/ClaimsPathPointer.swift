//
//  ClaimsPathPointer.swift
//  eudiWalletOidcIos
//

import Foundation

/// OpenID4VP 1.0 section 7, claims path pointer processing.
///
/// "A string value indicates that the respective key is to be selected, a null value indicates
/// that all elements of the currently selected array(s) are to be selected; and a non-negative
/// integer indicates that the respective index in an array is to be selected." The pointer arrives
/// as `[String?]`, so an integer component is a string of digits applied to an array.
///
/// For an mdoc (section 7.2) the pointer is `[namespace, element]` over the JSON the namespaces
/// were converted to, which the same walk covers.
enum ClaimsPathPointer {

    /// The selected elements, or nil when processing aborts under section 7.1.1: a key applied to
    /// something that is not an object, `null` or an index applied to something that is not an
    /// array, or an empty selection.
    ///
    /// One tolerance beyond the spec, kept from the previous filter: a string that holds a JSON
    /// object is entered like the object, because some credentials carry nested claims that way.
    static func select(_ root: Any, _ path: [String?]) -> [Any]? {
        if path.isEmpty { return nil }
        var selected: [Any] = [root]
        for component in path {
            var next: [Any] = []
            for element in selected {
                if component == nil {
                    guard let array = element as? [Any] else { return nil }
                    next.append(contentsOf: array)
                } else if let component, let array = element as? [Any], let index = Int(component), index >= 0,
                          component.allSatisfy({ $0.isASCII && $0.isNumber }) {
                    if index < array.count { next.append(array[index]) }
                } else if let component, let object = object(of: element) {
                    if let value = object[component] { next.append(value) }
                } else {
                    return nil
                }
            }
            if next.isEmpty { return nil }
            selected = next
        }
        return selected
    }

    /// Section 6.3: the selected value matches when its type and value equal one of `values`.
    static func matches(_ value: Any, _ values: [ClaimValue]) -> Bool {
        guard let claimValue = claimValue(value) else { return false }
        return values.contains(claimValue)
    }

    private static func object(of element: Any) -> [String: Any]? {
        if let object = element as? [String: Any] { return object }
        if let text = element as? String, text.hasPrefix("{") {
            return UIApplicationUtils.shared.convertStringToDictionary(text: text)
        }
        return nil
    }

    private static func claimValue(_ value: Any) -> ClaimValue? {
        if let number = value as? NSNumber {
            // JSONSerialization hands booleans over as NSNumber too; tell them apart first.
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return .bool(number.boolValue) }
            let double = number.doubleValue
            return double.rounded() == double ? .int(number.intValue) : nil
        }
        if let string = value as? String { return .string(string) }
        if let bool = value as? Bool { return .bool(bool) }
        if let int = value as? Int { return .int(int) }
        return nil
    }
}
