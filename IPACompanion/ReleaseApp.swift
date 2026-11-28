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
        guard signingMode.replacingOccurrences(of: " ", with: "") == "adhoc",
              let manifest,
              manifest.browser_download_url.scheme?.lowercased() == "https" else { return nil }
        // Apple expects the itms-services URL to have an authority delimiter:
        // itms-services://?action=download-manifest&url=<encoded HTTPS plist URL>
        guard var components = URLComponents(string: "itms-services://") else { return nil }
        let unreserved = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))
        guard let encodedManifestURL = manifest.browser_download_url.absoluteString.addingPercentEncoding(withAllowedCharacters: unreserved) else { return nil }
        // Encode the entire nested HTTPS URL as one query value. Leaving its
        // colon/slashes raw is accepted by generic URL parsers but is not the
        // canonical OTA form expected by iOS's installer.
        components.percentEncodedQuery = "action=download-manifest&url=\(encodedManifestURL)"
        return components.url
    }

    // Release notes commonly bold the entire label, including its colon:
    // **Bundle ID:** `com.example.app`. Split at the colon first, then
    // normalize the label instead of assuming Markdown ends before the colon.
    func value(_ label: String) -> String? {
        guard let body else { return nil }
        for rawLine in body.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let colon = line.firstIndex(of: ":") else { continue }
            var rawLabel = String(line[..<colon])
            rawLabel = rawLabel.replacingOccurrences(of: #"^\s*[-*]\s*"#, with: "", options: .regularExpression)
            let normalizedLabel = rawLabel
                .replacingOccurrences(of: "*", with: "")
                .replacingOccurrences(of: "_", with: "")
                .replacingOccurrences(of: "`", with: "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard normalizedLabel.caseInsensitiveCompare(label) == .orderedSame else { continue }
            let rawValue = String(line[line.index(after: colon)...])
            let result = Self.clean(rawValue)
            if !result.isEmpty { return result }
        }
        return nil
    }

    private static func clean(_ input: String) -> String {
        var value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        value = value.replacingOccurrences(of: "**", with: "")
        value = value.replacingOccurrences(of: "__", with: "")
        value = value.replacingOccurrences(of: "`", with: "")
        value = value.replacingOccurrences(of: #"^\s*\*(.*?)\*\s*$"#, with: "$1", options: .regularExpression)
        value = value.replacingOccurrences(of: #"^\s*_(.*?)_\s*$"#, with: "$1", options: .regularExpression)
        value = value.replacingOccurrences(of: #"^\s*\[(.*?)\]\([^)]*\)\s*$"#, with: "$1", options: .regularExpression)
        value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        while value.count >= 2 {
            let first = value.first!, last = value.last!
            if (first == "'" && last == "'") || (first == "\"" && last == "\"") || (first == "`" && last == "`") {
                value.removeFirst()
                value.removeLast()
                value = value.trimmingCharacters(in: .whitespacesAndNewlines)
            } else {
                break
            }
        }
        return value.replacingOccurrences(of: #"\s+"#, with: " ", options: .regularExpression)
    }
}
