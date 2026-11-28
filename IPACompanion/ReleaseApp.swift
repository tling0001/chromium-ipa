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
    var appName: String { value("App name") ?? value("App") ?? name }
    var bundleID: String? { value("Bundle ID") ?? value("Bundle identifier") }
    var appVersion: String? { value("App version") ?? value("Version") }
    var signingMode: String { (value("Signing mode") ?? "Unknown").lowercased() }
    var otaURL: URL? {
        guard signingMode.replacingOccurrences(of: " ", with: "") == "adhoc", let manifest else { return nil }
        var c = URLComponents()
        c.scheme = "itms-services"; c.queryItems = [URLQueryItem(name: "action", value: "download-manifest"), URLQueryItem(name: "url", value: manifest.browser_download_url.absoluteString)]
        return c.url
    }
    func value(_ label: String) -> String? {
        guard let body else { return nil }
        for line in body.components(separatedBy: .newlines) {
            if line.localizedCaseInsensitiveContains(label) {
                let parts=line.components(separatedBy: ":")
                if parts.count > 1 { return parts.dropFirst().joined(separator: ":").trimmingCharacters(in: .whitespaces) }
            }
        }
        return nil
    }
}
