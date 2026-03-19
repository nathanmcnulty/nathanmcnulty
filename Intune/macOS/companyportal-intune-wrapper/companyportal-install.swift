#!/usr/bin/env swift
import Cocoa
import ApplicationServices
import Foundation

enum InstallerError: Error, CustomStringConvertible {
    case usage(String)
    case accessibilityDenied
    case companyPortalNotRunning
    case companyPortalWindowUnavailable
    case searchFieldNotFound
    case searchFailed(String)
    case resultNotFound(String)
    case detailsNotOpened(String)
    case installButtonMissing
    case installPressFailed
    case installRequestNotObserved(String)
    case statusTimeout(String)
    case appNameResolutionFailed(String)

    var description: String {
        switch self {
        case .usage(let message):
            return message
        case .accessibilityDenied:
            return "Accessibility permission is required for the AX automation path."
        case .companyPortalNotRunning:
            return "Company Portal is not running after launch attempt."
        case .companyPortalWindowUnavailable:
            return "Company Portal window did not become available."
        case .searchFieldNotFound:
            return "Company Portal Apps search field was not found."
        case .searchFailed(let name):
            return "Failed to search for app '\(name)'."
        case .resultNotFound(let name):
            return "Search result for app '\(name)' was not found."
        case .detailsNotOpened(let target):
            return "Company Portal details page did not open for '\(target)'."
        case .installButtonMissing:
            return "Install button was not found on the app details page."
        case .installPressFailed:
            return "Install button press failed."
        case .installRequestNotObserved(let guid):
            return "Did not observe Company Portal submit the backend Install request for app GUID \(guid)."
        case .statusTimeout(let guid):
            return "Timed out waiting for an installation status update for app GUID \(guid)."
        case .appNameResolutionFailed(let guid):
            return "Could not resolve an app name from Company Portal logs for app GUID \(guid)."
        }
    }

    var exitCode: Int32 {
        switch self {
        case .usage:
            return 64
        case .accessibilityDenied:
            return 10
        case .companyPortalNotRunning:
            return 11
        case .companyPortalWindowUnavailable:
            return 12
        case .searchFieldNotFound:
            return 13
        case .searchFailed:
            return 14
        case .resultNotFound:
            return 15
        case .detailsNotOpened:
            return 16
        case .installButtonMissing:
            return 17
        case .installPressFailed:
            return 18
        case .installRequestNotObserved:
            return 19
        case .statusTimeout:
            return 20
        case .appNameResolutionFailed:
            return 21
        }
    }
}

enum OutputMode: String {
    case text
    case json
    case intune
}

struct AppRequest {
    var appName: String?
    var appGuid: String?

    var displayTarget: String {
        if let appName, !appName.isEmpty {
            return appName
        }

        if let appGuid, !appGuid.isEmpty {
            return appGuid
        }

        return "<unknown>"
    }
}

struct Config {
    var appRequests: [AppRequest] = []
    var launchTimeout: TimeInterval = 20
    var uiTimeout: TimeInterval = 20
    var requestTimeout: TimeInterval = 30
    var statusTimeout: TimeInterval = 180
    var waitForInstalled = false
    var continueOnError = false
    var returnFocus = true
    var settleDelay: TimeInterval = 1.0
    var verbose = false
    var outputMode: OutputMode = .text
}

struct InstallItemResult: Codable {
    let success: Bool
    let method: String
    let appGuid: String?
    let appName: String?
    let deviceGuid: String?
    let combinedStatus: String?
    let exitCode: Int32
    let message: String
    let skipped: Bool
}

struct InstallResult: Codable {
    let success: Bool
    let method: String
    let appGuid: String?
    let appName: String?
    let deviceGuid: String?
    let combinedStatus: String?
    let exitCode: Int32
    let message: String
    let skipped: Bool
    let items: [InstallItemResult]?
}

let companyPortalBundleID = "com.microsoft.CompanyPortalMac"

func stderr(_ message: String) {
    FileHandle.standardError.write(Data((message + "\n").utf8))
}

func log(_ config: Config, _ message: String) {
    if config.verbose {
        print("[companyportal-install] \(message)")
    }
}

func requestedOutputMode(from args: [String]) -> OutputMode {
    var index = 0
    while index < args.count {
        if args[index] == "--output", index + 1 < args.count {
            return OutputMode(rawValue: args[index + 1]) ?? .text
        }
        index += 1
    }
    return .text
}

func emit(result: InstallResult, outputMode: OutputMode) {
    switch outputMode {
    case .text:
        print(result.message)
        if let status = result.combinedStatus {
            print("Observed status: \(status)")
        }
        if let items = result.items, items.count > 1 {
            for item in items {
                let outcome = item.success ? (item.skipped ? "SKIPPED" : "OK") : "FAILED"
                let name = item.appName ?? item.appGuid ?? "<unknown>"
                var line = "[\(outcome)] \(name): \(item.message)"
                if let status = item.combinedStatus {
                    line += " (status=\(status))"
                }
                print(line)
            }
        }
    case .json:
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        if let data = try? encoder.encode(result), let text = String(data: data, encoding: .utf8) {
            print(text)
        } else {
            print("{\"success\":false,\"exitCode\":1,\"message\":\"Failed to encode JSON result.\"}")
        }
    case .intune:
        var fields: [String] = []
        fields.append("success=\(result.success ? "true" : "false")")
        fields.append("exitCode=\(result.exitCode)")
        fields.append("method=\(result.method)")
        if let appGuid = result.appGuid {
            fields.append("appGuid=\(appGuid)")
        }
        if let appName = result.appName {
            fields.append("appName=\(appName.replacingOccurrences(of: " ", with: "_"))")
        }
        if let deviceGuid = result.deviceGuid {
            fields.append("deviceGuid=\(deviceGuid)")
        }
        if let combinedStatus = result.combinedStatus {
            fields.append("combinedStatus=\(combinedStatus)")
        }
        fields.append("skipped=\(result.skipped ? "true" : "false")")
        if let items = result.items {
            fields.append("itemCount=\(items.count)")
            fields.append("successCount=\(items.filter { $0.success }.count)")
        }
        fields.append("message=\(result.message.replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: " ", with: "_"))")
        print(fields.joined(separator: " "))
    }
}

func appRequest(from spec: String) -> AppRequest {
    let trimmed = spec.trimmingCharacters(in: .whitespacesAndNewlines)
    let parts = trimmed.split(separator: "|", maxSplits: 1, omittingEmptySubsequences: false).map {
        String($0).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    if parts.count == 2 {
        return AppRequest(appName: parts[1].isEmpty ? nil : parts[1], appGuid: parts[0].isEmpty ? nil : parts[0])
    }

    if trimmed.contains("-") && trimmed.count >= 32 {
        return AppRequest(appName: nil, appGuid: trimmed)
    }

    return AppRequest(appName: trimmed.isEmpty ? nil : trimmed, appGuid: nil)
}

func loadAppRequests(from filePath: String) throws -> [AppRequest] {
    let url = URL(fileURLWithPath: filePath)
    let text = try String(contentsOf: url, encoding: .utf8)
    return text
        .split(separator: "\n", omittingEmptySubsequences: false)
        .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { !$0.isEmpty && !$0.hasPrefix("#") }
        .map { appRequest(from: $0) }
}

func deduplicated(_ requests: [AppRequest]) -> [AppRequest] {
    var seen = Set<String>()
    var result: [AppRequest] = []

    for request in requests {
        let key = "\(request.appGuid ?? "")|\(request.appName ?? "")".lowercased()
        if seen.insert(key).inserted {
            result.append(request)
        }
    }

    return result
}

let usageText = """
Usage:
  companyportal-install.swift --app-guid <guid> [--app-name <name>] [--wait-for-installed] [--verbose]
  companyportal-install.swift --app-name <name> [--verbose]
  companyportal-install.swift --app <spec> [--app <spec> ...] [--continue-on-error]
  companyportal-install.swift --apps-file <path> [--continue-on-error]

Options:
  --app-guid <guid>         Intune/Company Portal application GUID.
  --app-name <name>         Visible Company Portal app name.
  --app <spec>              Add one app request. Formats: <guid>, <name>, or <guid>|<name>.
  --apps-file <path>        Load app requests from a file, one per line. Format matches --app.
  --launch-timeout <sec>    Time to wait for Company Portal to launch. Default: 20
  --ui-timeout <sec>        Time to wait for UI transitions. Default: 20
  --request-timeout <sec>   Time to wait for backend Install request log entry. Default: 30
  --status-timeout <sec>    Time to wait for Installed status when enabled. Default: 180
  --wait-for-installed      Wait until Company Portal reports CombinedStatus=Installed.
  --continue-on-error       Continue processing later apps if one app fails.
  --no-return-focus         Leave Company Portal frontmost instead of restoring the prior app.
  --settle-delay <sec>      Delay between batch items. Default: 1.0
  --output <text|json|intune>
                            Output mode. Use json or intune for machine-readable output.
  --verbose                 Emit progress logging.
"""

func parseArgs() throws -> Config {
    var config = Config()
    let args = Array(CommandLine.arguments.dropFirst())
    var index = 0
    var legacyAppName: String?
    var legacyAppGuid: String?

    func requireValue(for option: String) throws -> String {
        index += 1
        guard index < args.count else {
            throw InstallerError.usage("Missing value for \(option).")
        }
        return args[index]
    }

    while index < args.count {
        let arg = args[index]
        switch arg {
        case "--app-name":
            legacyAppName = try requireValue(for: arg)
        case "--app-guid":
            legacyAppGuid = try requireValue(for: arg)
        case "--app":
            config.appRequests.append(appRequest(from: try requireValue(for: arg)))
        case "--apps-file":
            config.appRequests.append(contentsOf: try loadAppRequests(from: requireValue(for: arg)))
        case "--launch-timeout":
            config.launchTimeout = TimeInterval(try requireValue(for: arg)) ?? config.launchTimeout
        case "--ui-timeout":
            config.uiTimeout = TimeInterval(try requireValue(for: arg)) ?? config.uiTimeout
        case "--request-timeout":
            config.requestTimeout = TimeInterval(try requireValue(for: arg)) ?? config.requestTimeout
        case "--status-timeout":
            config.statusTimeout = TimeInterval(try requireValue(for: arg)) ?? config.statusTimeout
        case "--wait-for-installed":
            config.waitForInstalled = true
        case "--continue-on-error":
            config.continueOnError = true
        case "--no-return-focus":
            config.returnFocus = false
        case "--settle-delay":
            config.settleDelay = TimeInterval(try requireValue(for: arg)) ?? config.settleDelay
        case "--verbose":
            config.verbose = true
        case "--output":
            let value = try requireValue(for: arg)
            guard let mode = OutputMode(rawValue: value) else {
                throw InstallerError.usage("Invalid value for --output: \(value). Expected text, json, or intune.\n\n\(usageText)")
            }
            config.outputMode = mode
        case "-h", "--help":
            throw InstallerError.usage(usageText)
        default:
            throw InstallerError.usage("Unknown argument: \(arg)\n\n\(usageText)")
        }
        index += 1
    }

    if legacyAppGuid != nil || legacyAppName != nil {
        config.appRequests.insert(AppRequest(appName: legacyAppName, appGuid: legacyAppGuid), at: 0)
    }

    config.appRequests = deduplicated(config.appRequests.filter { $0.appGuid != nil || $0.appName != nil })

    guard !config.appRequests.isEmpty else {
        throw InstallerError.usage("You must provide --app-guid, --app-name, --app, or --apps-file.\n\n\(usageText)")
    }

    if config.waitForInstalled && config.appRequests.contains(where: { $0.appGuid == nil }) {
        throw InstallerError.usage("--wait-for-installed requires a GUID for each target app.\n\n\(usageText)")
    }

    return config
}

func axAttr(_ element: AXUIElement, _ name: String) -> AnyObject? {
    var value: CFTypeRef?
    return AXUIElementCopyAttributeValue(element, name as CFString, &value) == .success ? value : nil
}

func axString(_ element: AXUIElement, _ name: String) -> String {
    guard let value = axAttr(element, name) else { return "" }
    if CFGetTypeID(value) == CFStringGetTypeID() {
        return value as! String
    }
    return String(describing: value)
}

func axChildren(_ element: AXUIElement) -> [AXUIElement] {
    (axAttr(element, kAXChildrenAttribute as String) as? [AXUIElement]) ?? []
}

func axDescendants(_ element: AXUIElement) -> [AXUIElement] {
    var result = [element]
    for child in axChildren(element) {
        result.append(contentsOf: axDescendants(child))
    }
    return result
}

func axPress(_ element: AXUIElement) -> Bool {
    AXUIElementPerformAction(element, kAXPressAction as CFString) == .success
}

func waitFor(_ timeout: TimeInterval, poll: TimeInterval = 0.35, _ predicate: () -> Bool) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if predicate() {
            return true
        }
        RunLoop.current.run(until: Date().addingTimeInterval(poll))
    }
    return false
}

func companyPortalApp() -> NSRunningApplication? {
    NSRunningApplication.runningApplications(withBundleIdentifier: companyPortalBundleID).first
}

func frontmostApplication() -> NSRunningApplication? {
    NSWorkspace.shared.frontmostApplication
}

func firstWindow() -> AXUIElement? {
    guard let app = companyPortalApp() else { return nil }
    let axApp = AXUIElementCreateApplication(app.processIdentifier)
    return (axAttr(axApp, kAXWindowsAttribute as String) as? [AXUIElement])?.first
}

func ensureAccessibility() -> Bool {
    let options = [kAXTrustedCheckOptionPrompt.takeRetainedValue() as String: true] as CFDictionary
    return AXIsProcessTrustedWithOptions(options)
}

func restoreFocus(to application: NSRunningApplication?, config: Config) {
    guard config.returnFocus, let application else { return }
    application.activate(options: [])
}

func latestCompanyPortalLogURL() -> URL? {
    let logsDir = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Logs/Company Portal", isDirectory: true)
    let fm = FileManager.default
    guard let files = try? fm.contentsOfDirectory(at: logsDir, includingPropertiesForKeys: [.contentModificationDateKey], options: [.skipsHiddenFiles]) else {
        return nil
    }
    return files.max { lhs, rhs in
        let leftDate = (try? lhs.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
        let rightDate = (try? rhs.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
        return leftDate < rightDate
    }
}

func recentCompanyPortalLogURLs(limit: Int = 5) -> [URL] {
    let logsDir = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Logs/Company Portal", isDirectory: true)
    let fm = FileManager.default
    guard let files = try? fm.contentsOfDirectory(at: logsDir, includingPropertiesForKeys: [.contentModificationDateKey], options: [.skipsHiddenFiles]) else {
        return []
    }
    return files.sorted {
        let leftDate = (try? $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
        let rightDate = (try? $1.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
        return leftDate > rightDate
    }.prefix(limit).map { $0 }
}

func readLog(_ url: URL) -> String {
    (try? String(contentsOf: url, encoding: .utf8)) ?? ""
}

func firstRegexMatch(_ pattern: String, in text: String) -> String? {
    guard let regex = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]) else {
        return nil
    }
    let range = NSRange(text.startIndex..<text.endIndex, in: text)
    guard let match = regex.firstMatch(in: text, options: [], range: range), match.numberOfRanges > 1,
          let captureRange = Range(match.range(at: 1), in: text) else {
        return nil
    }
    return String(text[captureRange])
}

func resolveAppNameFromLogs(appGuid: String) -> String? {
    let escapedGuid = NSRegularExpression.escapedPattern(for: appGuid)
    let patterns = [
        "\\\"GuidKey\\\":\\s*\\\"\(escapedGuid)\\\".*?\\\"Name\\\":\\s*\\\"([^\\\"]+)\\\"",
        "\\\"Name\\\":\\s*\\\"([^\\\"]+)\\\".*?\\\"GuidKey\\\":\\s*\\\"\(escapedGuid)\\\""
    ]

    for logURL in recentCompanyPortalLogURLs() {
        let text = readLog(logURL)
        for pattern in patterns {
            if let name = firstRegexMatch(pattern, in: text), !name.isEmpty {
                return name
            }
        }
    }

    return nil
}

func openCompanyPortal(_ config: Config, appGuid: String?) throws {
    let priorFrontmost = frontmostApplication()
    let target = appGuid.map { "companyportal:/apps/\($0)" } ?? "companyportal:/apps"
    log(config, "Opening URL: \(target)")

    guard let url = URL(string: target) else {
        throw InstallerError.companyPortalNotRunning
    }

    NSWorkspace.shared.open(url)

    guard waitFor(config.launchTimeout, poll: 0.5, { companyPortalApp() != nil }) else {
        throw InstallerError.companyPortalNotRunning
    }

    _ = companyPortalApp()?.activate(options: [.activateAllWindows, .activateIgnoringOtherApps])

    guard waitFor(config.launchTimeout, poll: 0.5, { firstWindow() != nil }) else {
        throw InstallerError.companyPortalWindowUnavailable
    }

    restoreFocus(to: priorFrontmost, config: config)
}

func findSearchField() -> AXUIElement? {
    guard let window = firstWindow() else { return nil }
    return axDescendants(window).first {
        axString($0, kAXRoleAttribute as String) == "AXTextField" &&
        axString($0, kAXDescriptionAttribute as String) == "Search"
    }
}

func setSearchValue(_ value: String) -> Bool {
    guard let field = findSearchField() else { return false }
    let setResult = AXUIElementSetAttributeValue(field, kAXValueAttribute as CFString, value as CFTypeRef)
    guard setResult == .success else { return false }
    let confirmResult = AXUIElementPerformAction(field, kAXConfirmAction as CFString)
    return confirmResult == .success
}

func findResultButton(named appName: String) -> AXUIElement? {
    guard let window = firstWindow() else { return nil }
    return axDescendants(window).first {
        let role = axString($0, kAXRoleAttribute as String)
        let desc = axString($0, kAXDescriptionAttribute as String)
        if role != "AXButton" {
            return false
        }
        return desc.localizedCaseInsensitiveContains("App name: \(appName)") || desc.caseInsensitiveCompare(appName) == .orderedSame
    }
}

func findInstallButton() -> AXUIElement? {
    guard let window = firstWindow() else { return nil }
    return axDescendants(window).first {
        let role = axString($0, kAXRoleAttribute as String)
        let title = axString($0, kAXTitleAttribute as String)
        let desc = axString($0, kAXDescriptionAttribute as String)
        if role != "AXButton" {
            return false
        }
        return title == "Install" || desc == "Install"
    }
}

func searchAndOpenDetails(_ config: Config, appName: String) throws {
    log(config, "Searching for app by name: \(appName)")
    guard waitFor(config.uiTimeout, { findSearchField() != nil }) else {
        throw InstallerError.searchFieldNotFound
    }

    guard setSearchValue(appName) else {
        throw InstallerError.searchFailed(appName)
    }

    var button: AXUIElement?
    guard waitFor(config.uiTimeout, {
        button = findResultButton(named: appName)
        return button != nil
    }) else {
        throw InstallerError.resultNotFound(appName)
    }

    guard let result = button, axPress(result) else {
        throw InstallerError.detailsNotOpened(appName)
    }

    guard waitFor(config.uiTimeout, { findInstallButton() != nil || firstWindow() != nil }) else {
        throw InstallerError.detailsNotOpened(appName)
    }
}

func openDetailsByGuid(_ config: Config, appGuid: String, appNameFallback: String?) throws -> String? {
    try openCompanyPortal(config, appGuid: appGuid)

    if waitFor(8, { findInstallButton() != nil }) {
        log(config, "Direct app GUID navigation exposed an Install button.")
        return appNameFallback ?? resolveAppNameFromLogs(appGuid: appGuid)
    }

    let resolvedName = appNameFallback ?? resolveAppNameFromLogs(appGuid: appGuid)
    guard let appName = resolvedName else {
        throw InstallerError.appNameResolutionFailed(appGuid)
    }

    log(config, "Direct app GUID navigation did not expose Install quickly; falling back to Apps search.")
    try openCompanyPortal(config, appGuid: nil)
    try searchAndOpenDetails(config, appName: appName)
    return appName
}

func pressInstall(_ config: Config) throws {
    let priorFrontmost = frontmostApplication()
    var button: AXUIElement?
    guard waitFor(config.uiTimeout, {
        button = findInstallButton()
        return button != nil
    }) else {
        throw InstallerError.installButtonMissing
    }

    guard let installButton = button, axPress(installButton) else {
        throw InstallerError.installPressFailed
    }

    log(config, "Pressed Install.")
    restoreFocus(to: priorFrontmost, config: config)
}

func installRequestObserved(in logText: String, deviceGuid: String, appGuid: String) -> Bool {
    let requestNeedle = "ApplicationState(GuidKey1=guid'\(deviceGuid)',GuidKey2=guid'\(appGuid)')/Install?api-version="
    let successNeedle = "Successfully parsed response for request with url: https://"
    return logText.contains(requestNeedle) && logText.contains(successNeedle)
}

func combinedStatus(in logText: String, appGuid: String) -> String? {
    let lines = logText.split(separator: "\n")
    for line in lines.reversed() {
        let raw = String(line)
        if raw.contains(appGuid), raw.contains("CombinedStatus") {
            if let range = raw.range(of: "\"CombinedStatus\": \"") {
                let tail = raw[range.upperBound...]
                if let end = tail.firstIndex(of: "\"") {
                    return String(tail[..<end])
                }
            }
        }
    }
    return nil
}

func deviceGuid(in logText: String) -> String? {
    let pattern = "intune device id: "
    for line in logText.split(separator: "\n").reversed() {
        let raw = String(line)
        if let range = raw.range(of: pattern, options: [.caseInsensitive]) {
            return String(raw[range.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        }
        if let range = raw.range(of: "DeviceId\": \"") {
            let tail = raw[range.upperBound...]
            if let end = tail.firstIndex(of: "\"") {
                return String(tail[..<end]).uppercased()
            }
        }
    }
    return nil
}

func waitForInstallRequest(_ config: Config, appGuid: String, knownDeviceGuid: String?) throws -> String {
    guard let logURL = latestCompanyPortalLogURL() else {
        throw InstallerError.installRequestNotObserved(appGuid)
    }

    let initial = readLog(logURL)
    let resolvedDeviceGuid = knownDeviceGuid ?? deviceGuid(in: initial)

    guard let deviceGuid = resolvedDeviceGuid else {
        throw InstallerError.installRequestNotObserved(appGuid)
    }

    var finalLog = initial
    let observed = waitFor(config.requestTimeout, poll: 1.0) {
        finalLog = readLog(logURL)
        return installRequestObserved(in: finalLog, deviceGuid: deviceGuid.lowercased(), appGuid: appGuid.lowercased()) ||
            installRequestObserved(in: finalLog, deviceGuid: deviceGuid.uppercased(), appGuid: appGuid.lowercased())
    }

    guard observed else {
        throw InstallerError.installRequestNotObserved(appGuid)
    }

    return deviceGuid
}

func waitForInstalledStatus(_ config: Config, appGuid: String) throws -> String {
    guard let logURL = latestCompanyPortalLogURL() else {
        throw InstallerError.statusTimeout(appGuid)
    }

    var logText = readLog(logURL)
    if let status = combinedStatus(in: logText, appGuid: appGuid), status.caseInsensitiveCompare("Installed") == .orderedSame {
        return status
    }

    let observed = waitFor(config.statusTimeout, poll: 2.0) {
        logText = readLog(logURL)
        if let status = combinedStatus(in: logText, appGuid: appGuid) {
            return status.caseInsensitiveCompare("Installed") == .orderedSame
        }
        return false
    }

    guard observed, let status = combinedStatus(in: logText, appGuid: appGuid) else {
        throw InstallerError.statusTimeout(appGuid)
    }

    return status
}

func currentKnownStatus(appGuid: String) -> String? {
    for logURL in recentCompanyPortalLogURLs() {
        let text = readLog(logURL)
        if let status = combinedStatus(in: text, appGuid: appGuid) {
            return status
        }
    }
    return nil
}

func installInProgressStatus(_ status: String) -> Bool {
    ["installed", "downloading", "installing", "queued", "approvedforinstall"].contains(status.lowercased())
}

func performInstall(_ config: Config, request: AppRequest) throws -> InstallItemResult {
    var resolvedAppName = request.appName
    var resolvedDeviceGuid: String?
    var resolvedStatus: String?

    if let guid = request.appGuid {
        resolvedAppName = try openDetailsByGuid(config, appGuid: guid, appNameFallback: request.appName)
    } else if let name = request.appName {
        try openCompanyPortal(config, appGuid: nil)
        try searchAndOpenDetails(config, appName: name)
        resolvedAppName = name
    }

    do {
        try pressInstall(config)
    } catch InstallerError.installButtonMissing {
        if let guid = request.appGuid, let status = currentKnownStatus(appGuid: guid), installInProgressStatus(status) {
            return InstallItemResult(
                success: true,
                method: "company-portal-ax-guid",
                appGuid: guid,
                appName: resolvedAppName,
                deviceGuid: nil,
                combinedStatus: status,
                exitCode: 0,
                message: "Install action was already satisfied for app GUID \(guid).",
                skipped: true
            )
        }
        throw InstallerError.installButtonMissing
    }

    if let guid = request.appGuid {
        resolvedDeviceGuid = try waitForInstallRequest(config, appGuid: guid, knownDeviceGuid: nil)
        if config.waitForInstalled {
            resolvedStatus = try waitForInstalledStatus(config, appGuid: guid)
        }
    }

    let method = request.appGuid != nil ? "company-portal-ax-guid" : "company-portal-ax-name"
    let message: String
    if let guid = request.appGuid, let deviceGuid = resolvedDeviceGuid {
        message = "Install request submitted via Company Portal for app GUID \(guid) on device GUID \(deviceGuid)."
    } else if let name = resolvedAppName {
        message = "Install button pressed successfully for app '\(name)'."
    } else {
        message = "Install button pressed successfully via Company Portal."
    }

    return InstallItemResult(
        success: true,
        method: method,
        appGuid: request.appGuid,
        appName: resolvedAppName,
        deviceGuid: resolvedDeviceGuid,
        combinedStatus: resolvedStatus,
        exitCode: 0,
        message: message,
        skipped: false
    )
}

do {
    let rawArgs = Array(CommandLine.arguments.dropFirst())
    let fallbackOutputMode = requestedOutputMode(from: rawArgs)
    let config = try parseArgs()

    guard ensureAccessibility() else {
        throw InstallerError.accessibilityDenied
    }

    var itemResults: [InstallItemResult] = []
    var stopExitCode: Int32?

    for (index, request) in config.appRequests.enumerated() {
        log(config, "Processing app \(index + 1)/\(config.appRequests.count): \(request.displayTarget)")

        do {
            itemResults.append(try performInstall(config, request: request))
        } catch let error as InstallerError {
            let failure = InstallItemResult(
                success: false,
                method: request.appGuid != nil ? "company-portal-ax-guid" : "company-portal-ax-name",
                appGuid: request.appGuid,
                appName: request.appName,
                deviceGuid: nil,
                combinedStatus: nil,
                exitCode: error.exitCode,
                message: error.description,
                skipped: false
            )
            itemResults.append(failure)
            if !config.continueOnError {
                stopExitCode = error.exitCode
                break
            }
        }

        if index < config.appRequests.count - 1, config.settleDelay > 0 {
            RunLoop.current.run(until: Date().addingTimeInterval(config.settleDelay))
        }
    }

    let successCount = itemResults.filter { $0.success }.count
    let failureCount = itemResults.count - successCount
    let primary = itemResults.first
    let exitCode = stopExitCode ?? (failureCount == 0 ? 0 : 1)
    let message: String

    if itemResults.count == 1, let primary {
        message = primary.message
    } else {
        message = "Processed \(itemResults.count) apps via Company Portal. successes=\(successCount) failures=\(failureCount)."
    }

    emit(
        result: InstallResult(
            success: failureCount == 0,
            method: itemResults.count > 1 ? "company-portal-ax-batch" : (primary?.method ?? "company-portal-ax"),
            appGuid: primary?.appGuid,
            appName: primary?.appName,
            deviceGuid: primary?.deviceGuid,
            combinedStatus: primary?.combinedStatus,
            exitCode: exitCode,
            message: message,
            skipped: primary?.skipped ?? false,
            items: itemResults.count > 1 ? itemResults : nil
        ),
        outputMode: config.outputMode
    )

    exit(exitCode)
} catch let error as InstallerError {
    let fallbackOutputMode = requestedOutputMode(from: Array(CommandLine.arguments.dropFirst()))
    emit(
        result: InstallResult(
            success: false,
            method: "company-portal-ax",
            appGuid: nil,
            appName: nil,
            deviceGuid: nil,
            combinedStatus: nil,
            exitCode: error.exitCode,
            message: error.description,
            skipped: false,
            items: nil
        ),
        outputMode: fallbackOutputMode
    )
    if fallbackOutputMode == .text {
        stderr("error: \(error.description)")
    }
    exit(error.exitCode)
} catch {
    let fallbackOutputMode = requestedOutputMode(from: Array(CommandLine.arguments.dropFirst()))
    emit(
        result: InstallResult(
            success: false,
            method: "company-portal-ax",
            appGuid: nil,
            appName: nil,
            deviceGuid: nil,
            combinedStatus: nil,
            exitCode: 1,
            message: error.localizedDescription,
            skipped: false,
            items: nil
        ),
        outputMode: fallbackOutputMode
    )
    if fallbackOutputMode == .text {
        stderr("error: \(error.localizedDescription)")
    }
    exit(1)
}
