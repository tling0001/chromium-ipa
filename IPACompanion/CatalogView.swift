import SwiftUI

@MainActor
final class CatalogModel: ObservableObject {
    @Published var releases:[ReleaseApp]=[]
    @Published var loading=false
    @Published var error:String?
    @Published var tracked:[String:String]=UserDefaults.standard.dictionary(forKey:"trackedVersions") as? [String:String] ?? [:]
    private let endpoint=URL(string:"https://api.github.com/repos/tling0001/chromium-ipa/releases?per_page=100")!
    func track(_ app:ReleaseApp,installedVersion:String){tracked[app.bundleID ?? app.appName]=installedVersion;UserDefaults.standard.set(tracked,forKey:"trackedVersions")}
    func untrack(_ app:ReleaseApp){tracked.removeValue(forKey:app.bundleID ?? app.appName);UserDefaults.standard.set(tracked,forKey:"trackedVersions")}
    func trackedVersion(_ app:ReleaseApp)->String?{tracked[app.bundleID ?? app.appName]}
    func isTracked(_ app:ReleaseApp)->Bool{trackedVersion(app) != nil}
    func hasUpdate(_ app:ReleaseApp)->Bool{guard let installed=trackedVersion(app),let latest=app.appVersion else{return false};return compareVersions(latest,installed)>0}
    private func compareVersions(_ lhs:String,_ rhs:String)->Int{
        let a=lhs.split(whereSeparator:{ !$0.isNumber }).compactMap{Int($0)},b=rhs.split(whereSeparator:{ !$0.isNumber }).compactMap{Int($0)}
        for i in 0..<max(a.count,b.count){let x=i<a.count ? a[i]:0,y=i<b.count ? b[i]:0;if x != y{return x>y ? 1:-1}};return 0
    }
    func load() async{guard !loading else{return};loading=true;error=nil;defer{loading=false}
        do{var request=URLRequest(url:endpoint);request.setValue("application/vnd.github+json",forHTTPHeaderField:"Accept");let(data,response)=try await URLSession.shared.data(for:request);guard (response as? HTTPURLResponse)?.statusCode==200 else{throw URLError(.badServerResponse)};releases=try JSONDecoder().decode([ReleaseApp].self,from:data).filter{$0.ipa != nil && $0.bundleID != nil}
        }catch{self.error="Unable to load releases: \(error.localizedDescription)"}
    }
    var catalog:[ReleaseApp]{Dictionary(grouping:releases,by:{$0.bundleID ?? $0.appName}).values.compactMap{$0.sorted{($0.published_at ?? "") > ($1.published_at ?? "")}.first}.sorted{($0.published_at ?? "") > ($1.published_at ?? "")}}
    func icon(for app:ReleaseApp)->ReleaseApp.Asset? {
        let key = app.bundleID ?? app.appName
        return releases
            .filter { ($0.bundleID ?? $0.appName) == key && $0.icon != nil }
            .sorted { ($0.published_at ?? "") > ($1.published_at ?? "") }
            .first?.icon
    }
    var trackedApps:[ReleaseApp]{catalog.filter{isTracked($0)}}
    var updateApps:[ReleaseApp]{trackedApps.filter{hasUpdate($0)}}
}

struct CatalogView:View{
    @StateObject private var model=CatalogModel()
    @State private var query=""
    @State private var selected:ReleaseApp?
    var filtered:[ReleaseApp]{model.catalog.filter{query.isEmpty || $0.appName.localizedCaseInsensitiveContains(query) || ($0.bundleID ?? "").localizedCaseInsensitiveContains(query)}
    }
    var body:some View{
        TabView{
            NavigationStack{
                catalogList(filtered)
                    .navigationTitle("IPA Library").toolbarBackground(.ultraThinMaterial,for:.navigationBar).toolbarBackground(.visible,for:.navigationBar)
                    .searchable(text:$query,prompt:"Search apps").toolbar{ToolbarItem(placement:.topBarTrailing){Button{Task{await model.load()}}label:{Image(systemName:"arrow.clockwise")}.glassButtonCompat()}}
            }.tabItem{Label("Catalog",systemImage:"square.grid.2x2")}
            NavigationStack{
                updatesList
                    .navigationTitle("Updates").toolbarBackground(.ultraThinMaterial,for:.navigationBar).toolbarBackground(.visible,for:.navigationBar)
                    .toolbar{ToolbarItem(placement:.topBarTrailing){Button{Task{await model.load()}}label:{Image(systemName:"arrow.clockwise")}.glassButtonCompat()}}
            }.tabItem{Label("Updates",systemImage:"arrow.up.circle")}.badge(model.updateApps.count)
        }
        .task{await model.load()}.refreshable{await model.load()}.sheet(item:$selected){app in ReleaseDetail(app:app,model:model).presentationDetents([.medium,.large]).presentationDragIndicator(.visible)}
    }
    @ViewBuilder private func catalogList(_ apps:[ReleaseApp])->some View{
        if model.loading && model.releases.isEmpty{ProgressView("Loading apps…")}
        else if let error=model.error,model.releases.isEmpty{ContentUnavailableView("Catalog unavailable",systemImage:"wifi.exclamationmark",description:Text(error)).overlay(alignment:.bottom){Button("Retry"){Task{await model.load()}}.padding(.bottom,40)}}
        else{List(apps){app in AppListRow(app:app,model:model,select:{selected=app})}.listStyle(.insetGrouped).scrollContentBackground(.hidden)}
    }
    private var updatesList:some View{
        List{
            if model.trackedApps.isEmpty{ContentUnavailableView("No tracked apps",systemImage:"bookmark",description:Text("Track apps from their catalog details to monitor version updates."))}
            if !model.updateApps.isEmpty{
                Section("Updates available"){
                    ForEach(model.updateApps){app in AppListRow(app:app,model:model,select:{selected=app})}
                }
            }
            let current=model.trackedApps.filter{!model.hasUpdate($0)}
            if !current.isEmpty{Section("Up to date"){
                ForEach(current){app in AppListRow(app:app,model:model,select:{selected=app})}
            }}
        }.listStyle(.insetGrouped).scrollContentBackground(.hidden)
    }
}

struct AppListRow:View{
    let app:ReleaseApp
    @ObservedObject var model:CatalogModel
    var select:()->Void
    var body:some View{
        HStack(spacing:12){
            Button(action:select){AppRow(app:app,icon:model.icon(for:app),trackedVersion:model.trackedVersion(app),updateAvailable:model.hasUpdate(app)).contentShape(Rectangle())}.buttonStyle(.plain)
            if app.signingMode.replacingOccurrences(of: " ", with: "") == "adhoc" {
                if let ota=app.otaURL {
                    Link(destination:ota){Label("Install",systemImage:"arrow.down.app").font(.subheadline.weight(.semibold))}
                        .buttonStyle(.borderedProminent).controlSize(.regular).fixedSize()
                        .accessibilityHint("Install this Ad Hoc app on this device")
                } else {
                    Button {} label: {
                        Label("Install",systemImage:"exclamationmark.circle")
                    }
                    .buttonStyle(.bordered).controlSize(.regular).disabled(true).fixedSize()
                    .accessibilityLabel("Install unavailable: no OTA manifest")
                }
            } else {
                Button(action:select){Image(systemName:"chevron.right").font(.caption).foregroundStyle(.secondary).padding(8)}
                    .buttonStyle(.plain).accessibilityLabel("App details")
            }
        }
    }
}

struct AppRow:View{
    let app:ReleaseApp
    var icon:ReleaseApp.Asset?=nil
    var trackedVersion:String?=nil
    var updateAvailable:Bool=false
    var body:some View{
        HStack(spacing:14){
            AsyncImage(url:(icon ?? app.icon)?.browser_download_url){image in image.resizable().scaledToFit()}placeholder:{Image(systemName:"app.fill").resizable().scaledToFit().padding(12).foregroundStyle(.secondary)}
                .frame(width:54,height:54).clipShape(RoundedRectangle(cornerRadius:13)).background(.thinMaterial,in:RoundedRectangle(cornerRadius:13))
            VStack(alignment:.leading,spacing:4){
                Text(app.appName).font(.headline);Text(app.bundleID ?? "").font(.caption).foregroundStyle(.secondary);Text("Version \(app.appVersion ?? app.tag_name)").font(.subheadline)
                if let trackedVersion{Text("Installed \(trackedVersion)").font(.caption).foregroundStyle(updateAvailable ? .orange:.secondary)}
                if updateAvailable{Label("Update available",systemImage:"arrow.up.circle.fill").font(.caption).foregroundStyle(.orange)}
            }
            Spacer(minLength:4)
        }.padding(.vertical,4)
    }
}

struct ReleaseDetail:View{
    let app:ReleaseApp
    @ObservedObject var model:CatalogModel
    @State private var installedVersion=""
    var body:some View{
        NavigationStack{List{
            Section{AppRow(app:app,icon:model.icon(for:app),trackedVersion:model.trackedVersion(app),updateAvailable:model.hasUpdate(app));LabeledContent("Bundle ID",value:app.bundleID ?? "Unknown");LabeledContent("Signing",value:app.signingMode.capitalized);LabeledContent("Version",value:app.appVersion ?? app.tag_name);if let date=app.published_at{LabeledContent("Published",value:date)}}
            Section("Track this app"){
                if let saved=model.trackedVersion(app){LabeledContent("Installed version",value:saved);if model.hasUpdate(app){Label("Update available",systemImage:"arrow.up.circle.fill").foregroundStyle(.orange)};Button("Remove tracking",role:.destructive){model.untrack(app)}}
                else{TextField("Installed version (e.g. 1.2.3)",text:$installedVersion).textInputAutocapitalization(.never);Button("Save installed version"){model.track(app,installedVersion:installedVersion.trimmingCharacters(in:.whitespaces))}.disabled(installedVersion.trimmingCharacters(in:.whitespaces).isEmpty);Text("Tracking is stored locally.").font(.footnote).foregroundStyle(.secondary)}
            }
            Section("Install / Update"){
                if model.hasUpdate(app),let ota=app.otaURL{Link(destination:ota){Label("Install update · Version \(app.appVersion ?? app.tag_name)",systemImage:"arrow.down.app.fill").font(.headline)}}
                else if let ota=app.otaURL{Link(destination:ota){Label("Install or update on device",systemImage:"arrow.down.app.fill").font(.headline)}}
                if let ipa=app.ipa{Link("Download IPA",destination:ipa.browser_download_url)};Link("View release on GitHub",destination:app.html_url)
            }
            Section("Limitations"){Text("iOS cannot automatically enumerate all installed apps or silently replace app binaries. Tracking is manual. OTA installation may replace an existing app only when signing, bundle ID and provisioning are compatible.")}
            if let notes=app.body,!notes.isEmpty{Section("Release notes"){Text(notes).textSelection(.enabled)}}
        }.navigationTitle(app.appName).navigationBarTitleDisplayMode(.inline)}
    }
}
private extension View{@ViewBuilder func glassButtonCompat()->some View{if #available(iOS 26.0,*){self.buttonStyle(.glass)}else{self.buttonStyle(.bordered)}}}
