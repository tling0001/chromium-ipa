import SwiftUI

@MainActor
final class CatalogModel: ObservableObject {
    @Published var releases: [ReleaseApp] = []
    @Published var loading = false
    @Published var error: String?
    private let endpoint = URL(string: "https://api.github.com/repos/tling0001/chromium-ipa/releases?per_page=100")!
    
    func load() async {
        guard !loading else { return }
        loading = true; error = nil
        defer { loading = false }
        do {
            var request = URLRequest(url: endpoint)
            request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
            let (data,response)=try await URLSession.shared.data(for: request)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
            releases=try JSONDecoder().decode([ReleaseApp].self,from:data).filter { $0.ipa != nil && $0.bundleID != nil }
        } catch { self.error="Unable to load releases: \(error.localizedDescription)" }
    }
    var catalog: [ReleaseApp] {
        Dictionary(grouping: releases, by: { $0.bundleID ?? $0.appName }).values.compactMap { group in group.sorted { ($0.published_at ?? "") > ($1.published_at ?? "") }.first }.sorted { ($0.published_at ?? "") > ($1.published_at ?? "") }
    }
}

struct CatalogView: View {
    @StateObject private var model = CatalogModel()
    @State private var query = ""
    @State private var selected: ReleaseApp?
    var filtered: [ReleaseApp] { model.catalog.filter { query.isEmpty || $0.appName.localizedCaseInsensitiveContains(query) || ($0.bundleID ?? "").localizedCaseInsensitiveContains(query) } }
    
    var body: some View {
        NavigationStack {
            Group {
                if model.loading && model.releases.isEmpty { ProgressView("Loading apps…") }
                else if let error=model.error, model.releases.isEmpty { ContentUnavailableView("Catalog unavailable", systemImage:"wifi.exclamationmark", description:Text(error)).overlay(alignment:.bottom){ Button("Retry"){Task{await model.load()}}.padding(.bottom,40) } }
                else { List(filtered) { app in Button { selected=app } label: { AppRow(app:app) }.buttonStyle(.plain) } }
            }
            .navigationTitle("IPA Library")
            .searchable(text:$query,prompt:"Search apps")
            .toolbar { ToolbarItem(placement:.topBarTrailing){ Button { Task{await model.load()} } label:{Image(systemName:"arrow.clockwise")} } }
            .task { await model.load() }
            .refreshable { await model.load() }
            .sheet(item:$selected){ app in ReleaseDetail(app:app) }
        }
    }
}

struct AppRow: View {
    let app: ReleaseApp
    var body: some View {
        HStack(spacing:14) {
            AsyncImage(url:app.icon?.browser_download_url){ image in image.resizable().scaledToFit() } placeholder:{ Image(systemName:"app.fill").resizable().scaledToFit().padding(12).foregroundStyle(.secondary) }
                .frame(width:54,height:54).clipShape(RoundedRectangle(cornerRadius:13))
            VStack(alignment:.leading,spacing:4) {
                Text(app.appName).font(.headline)
                Text(app.bundleID ?? "").font(.caption).foregroundStyle(.secondary)
                Text("Version \(app.appVersion ?? app.tag_name)").font(.subheadline)
            }
            Spacer()
            Text(app.signingMode.capitalized).font(.caption).padding(6).background(.thinMaterial).clipShape(Capsule())
        }.padding(.vertical,4)
    }
}

struct ReleaseDetail: View {
    let app: ReleaseApp
    var body: some View {
        NavigationStack {
            List {
                Section {
                    AppRow(app:app)
                    LabeledContent("Bundle ID",value:app.bundleID ?? "Unknown")
                    LabeledContent("Signing",value:app.signingMode.capitalized)
                    LabeledContent("Version",value:app.appVersion ?? app.tag_name)
                    if let date=app.published_at { LabeledContent("Published",value:date) }
                }
                Section("Install / Update") {
                    if let ota=app.otaURL {
                        Link(destination:ota){Label("Install or update on device",systemImage:"arrow.down.app.fill").font(.headline)}
                        Text("Open the OTA installation flow. The signed build and provisioning profile must support this device.").font(.footnote).foregroundStyle(.secondary)
                    }
                    if let ipa=app.ipa { Link("Download IPA",destination:ipa.browser_download_url) }
                    if let release=URL(string:app.html_url.absoluteString) { Link("View release on GitHub",destination:release) }
                }
                Section("Update limitations") {
                    Text("iOS does not allow this app to inspect every other app installed on your device or silently replace their binaries. If you install the same app with a compatible signing identity and provisioning profile, the OTA flow may install its newer version over the existing app.")
                }
                if let notes=app.body, !notes.isEmpty { Section("Release notes"){Text(notes).textSelection(.enabled)} }
            }.navigationTitle(app.appName).navigationBarTitleDisplayMode(.inline)
        }
    }
}
