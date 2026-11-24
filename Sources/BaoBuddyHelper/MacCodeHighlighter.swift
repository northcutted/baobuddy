#if os(macOS)
import AppKit
import SwiftUI

/// Supported languages for syntax-highlighted code boxes across the macOS BaoBuddy app.
enum MacCodeLanguage {
    case hcl
    case markdown
    case shell
    case json
    case pem
    case openSSH
}

/// Zero-dependency syntax highlighter producing adaptive SwiftUI `AttributedString` values
/// for HCL/OpenTofu, Markdown, CLI shell commands, JSON profiles, PEM keys, and OpenSSH public keys.
enum MacCodeHighlighter {
    private static let hclKeywords: Set<String> = [
        "terraform", "required_providers", "provider", "variable", "resource",
        "locals", "output", "validation", "for_each", "for", "in",
        "true", "false", "null", "string", "number", "bool", "list", "map", "object", "optional"
    ]

    private static let hclFunctions: Set<String> = [
        "compact", "concat", "join", "merge", "jsonencode", "contains",
        "length", "can", "regex", "alltrue", "try", "split"
    ]

    private static let keywordColor = Color(nsColor: .systemPurple)
    private static let functionColor = Color(nsColor: .systemBlue)
    private static let stringColor = Color(nsColor: .systemGreen)
    private static let numberColor = Color(nsColor: .systemOrange)
    private static let keyColor = MacBaoTheme.brand
    private static let commentColor = Color.secondary

    static func highlight(_ source: String, language: MacCodeLanguage) -> AttributedString {
        switch language {
        case .hcl: highlightHCL(source)
        case .markdown: highlightMarkdown(source)
        case .shell: highlightShell(source)
        case .json: highlightJSON(source)
        case .pem: highlightPEM(source)
        case .openSSH: highlightOpenSSH(source)
        }
    }

    static func highlight(_ source: String, fileName: String) -> AttributedString {
        if fileName.hasSuffix(".md") { return highlightMarkdown(source) }
        if fileName.hasSuffix(".json") { return highlightJSON(source) }
        return highlightHCL(source)
    }

    // MARK: - HCL / OpenTofu

    private static func highlightHCL(_ source: String) -> AttributedString {
        var output = AttributedString()
        let lines = source.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        var inHeredoc = false
        var heredocDelimiter = ""

        for (index, line) in lines.enumerated() {
            if index > 0 { output.append(AttributedString("\n")) }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if inHeredoc {
                var part = AttributedString(line)
                part.foregroundColor = trimmed == heredocDelimiter ? keywordColor : stringColor
                output.append(part)
                if trimmed == heredocDelimiter {
                    inHeredoc = false
                    heredocDelimiter = ""
                }
                continue
            }
            if trimmed.hasPrefix("#") || trimmed.hasPrefix("//") {
                var part = AttributedString(line)
                part.foregroundColor = commentColor
                output.append(part)
                continue
            }
            if let range = line.range(of: "<<-") ?? line.range(of: "<<") {
                let delim = line[range.upperBound...].trimmingCharacters(in: .whitespaces)
                if !delim.isEmpty {
                    output.append(highlightHCLLine(String(line[..<range.lowerBound])))
                    var marker = AttributedString(String(line[range.lowerBound...]))
                    marker.foregroundColor = keywordColor
                    output.append(marker)
                    inHeredoc = true
                    heredocDelimiter = delim
                    continue
                }
            }
            output.append(highlightHCLLine(line))
        }
        return output
    }

    private static func highlightHCLLine(_ line: String) -> AttributedString {
        var result = AttributedString()
        let chars = Array(line)
        var i = 0

        while i < chars.count {
            let ch = chars[i]
            if ch == "#" || (ch == "/" && i + 1 < chars.count && chars[i + 1] == "/") {
                var comment = AttributedString(String(chars[i...]))
                comment.foregroundColor = commentColor
                result.append(comment)
                break
            }
            if ch == "\"" {
                let end = scanQuotedString(chars, start: i)
                var str = AttributedString(String(chars[i..<end]))
                str.foregroundColor = stringColor
                result.append(str)
                i = end
                continue
            }
            if ch.isNumber && (i == 0 || (!chars[i - 1].isLetter && chars[i - 1] != "_")) {
                var j = i
                while j < chars.count && (chars[j].isNumber || chars[j] == ".") { j += 1 }
                var num = AttributedString(String(chars[i..<j]))
                num.foregroundColor = numberColor
                result.append(num)
                i = j
                continue
            }
            if ch.isLetter || ch == "_" {
                var j = i
                while j < chars.count && (chars[j].isLetter || chars[j].isNumber || chars[j] == "_" || chars[j] == "-") {
                    j += 1
                }
                let word = String(chars[i..<j])
                var token = AttributedString(word)
                var k = j
                while k < chars.count && chars[k] == " " { k += 1 }
                let nextChar: Character? = k < chars.count ? chars[k] : nil
                let isAssign = nextChar == "=" && (k + 1 >= chars.count || chars[k + 1] != "=")

                if hclKeywords.contains(word) {
                    token.foregroundColor = keywordColor
                } else if hclFunctions.contains(word) && nextChar == "(" {
                    token.foregroundColor = functionColor
                } else if isAssign {
                    token.foregroundColor = keyColor
                } else if word == "var" || word == "each" || word == "local" {
                    token.foregroundColor = functionColor
                }
                result.append(token)
                i = j
                continue
            }
            result.append(AttributedString(String(ch)))
            i += 1
        }
        return result
    }

    // MARK: - Markdown

    private static func highlightMarkdown(_ source: String) -> AttributedString {
        var output = AttributedString()
        let lines = source.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        var inCodeFence = false

        for (index, line) in lines.enumerated() {
            if index > 0 { output.append(AttributedString("\n")) }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("```") {
                inCodeFence.toggle()
                var fence = AttributedString(line)
                fence.foregroundColor = commentColor
                output.append(fence)
                continue
            }
            if inCodeFence {
                output.append(highlightShellLine(line))
                continue
            }
            if trimmed.hasPrefix("#") {
                var heading = AttributedString(line)
                heading.foregroundColor = keyColor
                heading.inlinePresentationIntent = .stronglyEmphasized
                output.append(heading)
                continue
            }
            output.append(AttributedString(line))
        }
        return output
    }

    // MARK: - Shell / CLI / Deep Links

    private static func highlightShell(_ source: String) -> AttributedString {
        var output = AttributedString()
        let lines = source.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        for (index, line) in lines.enumerated() {
            if index > 0 { output.append(AttributedString("\n")) }
            output.append(highlightShellLine(line))
        }
        return output
    }

    private static func highlightShellLine(_ line: String) -> AttributedString {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("#") {
            var comment = AttributedString(line)
            comment.foregroundColor = commentColor
            return comment
        }
        if trimmed.hasPrefix("baobuddy://") || trimmed.hasPrefix("https://") {
            var uri = AttributedString()
            if let qIdx = line.firstIndex(of: "?") {
                var base = AttributedString(String(line[..<qIdx]))
                base.foregroundColor = keyColor
                uri.append(base)
                var query = AttributedString(String(line[qIdx...]))
                query.foregroundColor = stringColor
                uri.append(query)
                return uri
            }
            var plain = AttributedString(line)
            plain.foregroundColor = keyColor
            return plain
        }

        var result = AttributedString()
        let chars = Array(line)
        var i = 0
        var wordIndex = 0

        while i < chars.count {
            let ch = chars[i]
            if ch.isWhitespace {
                var j = i
                while j < chars.count && chars[j].isWhitespace { j += 1 }
                result.append(AttributedString(String(chars[i..<j])))
                i = j
                continue
            }
            if ch == "\"" || ch == "'" {
                let end = scanQuotedString(chars, start: i, quote: ch)
                var str = AttributedString(String(chars[i..<end]))
                str.foregroundColor = stringColor
                result.append(str)
                i = end
                wordIndex += 1
                continue
            }
            var j = i
            while j < chars.count && !chars[j].isWhitespace { j += 1 }
            let word = String(chars[i..<j])
            var tok = AttributedString(word)
            if wordIndex == 0 {
                tok.foregroundColor = keyColor
                tok.inlinePresentationIntent = .stronglyEmphasized
            } else if word.hasPrefix("--") || word.hasPrefix("-") {
                tok.foregroundColor = keywordColor
            } else if word.hasPrefix("$") {
                tok.foregroundColor = numberColor
            } else if word == "|" || word == "&&" || word == ">" || word == "\\" {
                tok.foregroundColor = commentColor
            } else if wordIndex == 1 {
                tok.foregroundColor = functionColor
            } else if word.allSatisfy(\.isNumber) {
                tok.foregroundColor = numberColor
            } else if word.contains("=") {
                if let eq = word.firstIndex(of: "=") {
                    var lhs = AttributedString(String(word[..<eq]))
                    lhs.foregroundColor = keyColor
                    var eqTok = AttributedString("=")
                    eqTok.foregroundColor = commentColor
                    var rhs = AttributedString(String(word[word.index(after: eq)...]))
                    rhs.foregroundColor = stringColor
                    result.append(lhs)
                    result.append(eqTok)
                    result.append(rhs)
                    i = j
                    wordIndex += 1
                    continue
                }
            }
            result.append(tok)
            i = j
            wordIndex += 1
        }
        return result
    }

    // MARK: - JSON

    private static func highlightJSON(_ source: String) -> AttributedString {
        var result = AttributedString()
        let chars = Array(source)
        var i = 0

        while i < chars.count {
            let ch = chars[i]
            if ch == "\"" {
                let end = scanQuotedString(chars, start: i)
                var k = end
                while k < chars.count && (chars[k] == " " || chars[k] == "\t") { k += 1 }
                let isKey = k < chars.count && chars[k] == ":"
                var tok = AttributedString(String(chars[i..<end]))
                tok.foregroundColor = isKey ? keyColor : stringColor
                result.append(tok)
                i = end
                continue
            }
            if ch.isNumber || (ch == "-" && i + 1 < chars.count && chars[i + 1].isNumber) {
                var j = i + 1
                while j < chars.count && (chars[j].isNumber || chars[j] == ".") { j += 1 }
                var num = AttributedString(String(chars[i..<j]))
                num.foregroundColor = numberColor
                result.append(num)
                i = j
                continue
            }
            if ch.isLetter {
                var j = i
                while j < chars.count && chars[j].isLetter { j += 1 }
                let word = String(chars[i..<j])
                var tok = AttributedString(word)
                if word == "true" || word == "false" || word == "null" {
                    tok.foregroundColor = keywordColor
                }
                result.append(tok)
                i = j
                continue
            }
            var punct = AttributedString(String(ch))
            if "{}[]:,".contains(ch) {
                punct.foregroundColor = commentColor
            }
            result.append(punct)
            i += 1
        }
        return result
    }

    // MARK: - PEM & OpenSSH Public Keys

    private static func highlightPEM(_ source: String) -> AttributedString {
        var output = AttributedString()
        let lines = source.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        for (index, line) in lines.enumerated() {
            if index > 0 { output.append(AttributedString("\n")) }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            var tok = AttributedString(line)
            if trimmed.hasPrefix("-----BEGIN") || trimmed.hasPrefix("-----END") {
                tok.foregroundColor = keywordColor
                tok.inlinePresentationIntent = .stronglyEmphasized
            } else {
                tok.foregroundColor = stringColor
            }
            output.append(tok)
        }
        return output
    }

    private static func highlightOpenSSH(_ source: String) -> AttributedString {
        let parts = source.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 2 else { return AttributedString(source) }
        var output = AttributedString()
        var alg = AttributedString(parts[0])
        alg.foregroundColor = keywordColor
        alg.inlinePresentationIntent = .stronglyEmphasized
        output.append(alg)
        output.append(AttributedString(" "))
        var body = AttributedString(parts[1])
        body.foregroundColor = stringColor
        output.append(body)
        if parts.count == 3 {
            output.append(AttributedString(" "))
            var comment = AttributedString(parts[2])
            comment.foregroundColor = keyColor
            output.append(comment)
        }
        return output
    }

    private static func scanQuotedString(_ chars: [Character], start: Int, quote: Character = "\"") -> Int {
        var j = start + 1
        var escaped = false
        while j < chars.count {
            if escaped {
                escaped = false
            } else if chars[j] == "\\" {
                escaped = true
            } else if chars[j] == quote {
                return j + 1
            }
            j += 1
        }
        return j
    }
}

/// Reusable styled, syntax-highlighted code box for macOS Settings & sheets.
struct MacCodeBox: View {
    let text: String
    let language: MacCodeLanguage
    var fontSize: CGFloat = 11.5

    var body: some View {
        Text(MacCodeHighlighter.highlight(text, language: language))
            .font(.system(size: fontSize, design: .monospaced))
            .lineSpacing(2)
            .textSelection(.enabled)
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                Color(nsColor: .textBackgroundColor).opacity(0.65),
                in: RoundedRectangle(cornerRadius: 8, style: .continuous)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .strokeBorder(Color.primary.opacity(0.08), lineWidth: 1)
            )
    }
}
#endif
