import Foundation

struct ReleaseApp: Identifiable, Decodable {
    let id: Int
    let name: String
    let tag_name: String
    let body: String?
    let published_at: String?
    let html_url: URL
    let assets: [Asset]
    let prerelease: Bool

    struct Asset: Decodable, Identifiable {
        let id: Int
        let name: String
        let browser_download_url: URL
    }

    var ipa: Asset? { assets.first { $0.name.lowercased().hasSuffix(".ipa") } }
    var manifest: Asset? { assets.first { $0.name.lowercased() == "manifest.plist" } }
    var icon: Asset? { assets.first { $0.name.lowercased() == "app-icon.png" } }
    var appName: String { Self.clean(value("App name") ?? value("App") ?? name) }
    var bundleID: String? { value("Bundle ID") ?? value("Bundle identifier") }
    var appVersion: String? { value("App version") ?? value("Version") }
    var signingMode: String { (value("Signing mode") ?? "Unknown").lowercased() }

    var otaURL: URL? {
        guard signingMode.replacingOccurrences(of: " ", with: "") == "adhoc", let manifest else { return nil }
        var components = URLComponents()
        components.scheme = "itms-services"
        components.queryItems = [
            URLQueryItem(name: "action", value: "download-manifest"),
            URLQueryItem(name: "url", value: manifest.browser_download_url.absoluteString)
        ]
        return components.url
    }

    func value(_ label: String) -> String? {
        guard let body else { return nil }
        for line in body.components(separatedBy: .newlines) {
            let pattern = #"^\s*(?:[-*]\s*)?(?:\*{1,2})?\s*"# + NSRegularExpression.escapedPattern(for: label) + #"\s*(?:\*{1,2})?\s*:\s*(.*?)\s*$"#
            guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]),
                  let match = regex.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)),
                  let range = Range(match.range(at: 1), in: line) else { continue }
            let result = Self.clean(String(line[range]))
            if !result.isEmpty { return result }
        }
        return nil
    }

    private static func clean(_ input: String) -> String {
        var value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        // Strip common Markdown wrappers without changing meaningful punctuation.
        value = value.replacingOccurrences(of: #"^\s*(?:\*\*|__|\*|_)(.*?)(?:\*\*|__|\*|_)\s*$"#, with: "$1", options: .regularExpression)
        value = value.replacingOccurrences(of: #"^\s*\[(.*?)\]\([^)]*\)\s*$"#, with: "$1", options: .regularExpression)
        value = value.replacingOccurrences(of: #"^\s*`+(.*?)`+\s*$"#, with: "$1", options: .regularExpression)
        value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        // Release metadata is sometimes emitted as 'value', "value", or `value`.
        while value.count >= 2 {
            let first = value.first!, last = value.last!
            if (first == "'" && last == "'") || (first == "\"" && last == "\"") || (first == "`" && last == "`") {
                value.removeFirst(); value.removeLast()
                value = value.trimmingCharacters(in: .whitespacesAndNewlines)
            } else { break }
        }
        return value.replacingOccurrences(of: #"\s+"#, with: " ", options: .regularExpression)
    }
}
