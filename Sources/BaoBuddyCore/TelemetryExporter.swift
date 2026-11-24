import Foundation

/// Optional OpenTelemetry OTLP/HTTP configuration for enterprise SIEM ingestion.
/// Disabled by default (zero telemetry unless explicitly configured by an operator or MDM).
public struct BaoTelemetryConfig: Codable, Equatable, Sendable {
    public var otlpEndpoint: String
    public var serviceName: String
    public var headers: [String: String]

    public static let disabled = BaoTelemetryConfig()

    public var isEnabled: Bool {
        !otlpEndpoint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    enum CodingKeys: String, CodingKey {
        case otlpEndpoint = "otlp_endpoint"
        case serviceName = "service_name"
        case headers
    }

    public init(
        otlpEndpoint: String = "",
        serviceName: String = "baobuddy-client",
        headers: [String: String] = [:]
    ) {
        self.otlpEndpoint = otlpEndpoint
        self.serviceName = serviceName
        self.headers = headers
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.otlpEndpoint = try container.decodeIfPresent(String.self, forKey: .otlpEndpoint) ?? ""
        self.serviceName = try container.decodeIfPresent(String.self, forKey: .serviceName) ?? "baobuddy-client"
        self.headers = try container.decodeIfPresent([String: String].self, forKey: .headers) ?? [:]
    }
}

/// Zero-dependency OpenTelemetry OTLP/HTTP JSON exporter (`/v1/logs` and `/v1/metrics`).
/// Emits strictly non-secret metadata from `GrantActivityEntry`; never transmits tokens or keys.
public struct BaoOTLPExporter: Sendable {
    public let config: BaoTelemetryConfig
    public let transport: any HTTPTransport

    public init(config: BaoTelemetryConfig, transport: (any HTTPTransport)? = nil) throws {
        self.config = config
        if let transport {
            self.transport = transport
        } else {
            self.transport = try PinnedTLSClient(caPEM: "", timeoutInterval: 4)
        }
    }

    /// Emits an OTLP/HTTP log record and delta counter metric for a grant lifecycle event.
    public func emit(entry: GrantActivityEntry, actor: String = "") async {
        guard config.isEnabled else { return }
        let base = config.otlpEndpoint.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let logsURL = URL(string: "\(base)/v1/logs"),
              let metricsURL = URL(string: "\(base)/v1/metrics") else {
            return
        }

        let nowNano = String(Int64(entry.timestamp.timeIntervalSince1970 * 1_000_000_000))
        let service = config.serviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        let resourceAttrs = [
            kvString("service.name", service.isEmpty ? "baobuddy-client" : service),
            kvString("baobuddy.via", entry.via)
        ]

        var eventAttrs: [[String: Any]] = [
            kvString("baobuddy.action", entry.action.rawValue),
            kvString("baobuddy.server", entry.serverName),
            kvString("baobuddy.target", entry.targetName),
            kvBool("baobuddy.elevated", entry.elevated),
            kvString("baobuddy.via", entry.via)
        ]
        if !actor.isEmpty { eventAttrs.append(kvString("enduser.id", actor)) }
        if !entry.namespace.isEmpty { eventAttrs.append(kvString("baobuddy.namespace", entry.namespace)) }
        if !entry.policies.isEmpty { eventAttrs.append(kvString("baobuddy.policies", entry.policies.joined(separator: ","))) }
        if entry.hours > 0 { eventAttrs.append(kvInt("baobuddy.hours", entry.hours)) }
        if !entry.why.isEmpty { eventAttrs.append(kvString("baobuddy.why", entry.why)) }

        let logBody: [String: Any] = [
            "resourceLogs": [[
                "resource": ["attributes": resourceAttrs],
                "scopeLogs": [[
                    "scope": ["name": "baobuddy.core", "version": "0.1.0"],
                    "logRecords": [[
                        "timeUnixNano": nowNano,
                        "severityNumber": entry.elevated ? 13 : 9,
                        "severityText": entry.elevated ? "WARN" : "INFO",
                        "body": ["stringValue": "\(entry.action.displayTitle): \(entry.serverName) -> \(entry.targetName)"],
                        "attributes": eventAttrs
                    ]]
                ]]
            ]]
        ]

        let metricBody: [String: Any] = [
            "resourceMetrics": [[
                "resource": ["attributes": resourceAttrs],
                "scopeMetrics": [[
                    "scope": ["name": "baobuddy.core", "version": "0.1.0"],
                    "metrics": [[
                        "name": "baobuddy.client.events",
                        "description": "Count of BaoBuddy client grant approvals and revocations",
                        "unit": "1",
                        "sum": [
                            "isMonotonic": true,
                            "aggregationTemporality": 1,
                            "dataPoints": [[
                                "startTimeUnixNano": nowNano,
                                "timeUnixNano": nowNano,
                                "asInt": "1",
                                "attributes": [
                                    kvString("baobuddy.action", entry.action.rawValue),
                                    kvString("baobuddy.server", entry.serverName),
                                    kvString("baobuddy.namespace", entry.namespace),
                                    kvBool("baobuddy.elevated", entry.elevated),
                                    kvString("baobuddy.via", entry.via)
                                ]
                            ]]
                        ]
                    ]]
                ]]
            ]]
        ]

        await post(url: logsURL, json: logBody)
        await post(url: metricsURL, json: metricBody)
    }

    private func post(url: URL, json: [String: Any]) async {
        guard let data = try? JSONSerialization.data(withJSONObject: json) else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        for (key, value) in config.headers {
            req.setValue(value, forHTTPHeaderField: key)
        }
        req.httpBody = data
        _ = try? await transport.send(req)
    }

    private func kvString(_ key: String, _ value: String) -> [String: Any] {
        ["key": key, "value": ["stringValue": value]]
    }

    private func kvInt(_ key: String, _ value: Int) -> [String: Any] {
        ["key": key, "value": ["intValue": String(value)]]
    }

    private func kvBool(_ key: String, _ value: Bool) -> [String: Any] {
        ["key": key, "value": ["boolValue": value]]
    }
}
