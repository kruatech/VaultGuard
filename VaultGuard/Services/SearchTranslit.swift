import Foundation

/// Query expansion for the item-list search field.
///
/// The vault's searchable text is left untouched — only the user's query is expanded into a
/// small set of equivalent spellings, so the same field finds an entry whichever script or
/// keyboard layout the user happened to be in:
///
///   "гит" -> "git" -> matches "github"
///   "git" -> "гит" -> matches "Гитхаб"
///   "пше" -> "git" -> matches "github"   (ЙЦУКЕН keys typed while QWERTY was meant)
///
/// Expanding the query rather than folding the data keeps the index a plain lowercased
/// string, costs one pass per keystroke instead of one pass per item, and never widens what
/// a stored value can match on its own.
///
/// Scope note: this is the UI search only. AutoFill host matching (`AutoFillVault`) must stay
/// exact — loosening it there would let look-alike domains match.
enum SearchQueryExpander {

    /// Queries shorter than this are used verbatim. Two Cyrillic letters transliterate into
    /// fragments ("я" -> "ya") that match far too much to be useful.
    static let minLengthForExpansion = 2

    /// Upper bound on the generated set. Ambiguous letters branch (х -> h/kh/x), so without a
    /// cap a long query would expand combinatorially. The primary spelling is always produced
    /// first, so truncation only ever drops secondary branches.
    static let maxVariants = 12

    /// All spellings to test the query against. Element 0 is always the query as typed.
    static func variants(for raw: String) -> [String] {
        let q = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return [] }

        var out: [String] = [q]
        guard q.count >= minLengthForExpansion else { return out }

        func add(_ candidates: [String]) {
            for c in candidates {
                guard out.count < maxVariants else { return }
                guard !c.isEmpty, !out.contains(c) else { continue }
                out.append(c)
            }
        }

        let hasCyr = containsCyrillic(q)
        let hasLat = containsLatin(q)

        if hasCyr {
            add(cyrillicToLatin(q))
            add([mapKeys(q, using: ruKeyToEnKey)])
        }
        if hasLat {
            add(latinToCyrillic(q))
            add([mapKeys(q, using: enKeyToRuKey)])
        }
        return out
    }

    // MARK: - Script detection

    private static func containsCyrillic(_ s: String) -> Bool {
        s.unicodeScalars.contains {
            ($0.value >= 0x0410 && $0.value <= 0x044F) || $0.value == 0x0401 || $0.value == 0x0451
        }
    }

    private static func containsLatin(_ s: String) -> Bool {
        s.unicodeScalars.contains {
            ($0.value >= 0x61 && $0.value <= 0x7A) || ($0.value >= 0x41 && $0.value <= 0x5A)
        }
    }

    // MARK: - Cyrillic -> Latin

    /// First element of each list is the primary spelling; the rest are common alternatives.
    private static let cyrToLat: [Character: [String]] = [
        "а": ["a"],  "б": ["b"],  "в": ["v"],  "г": ["g"],  "д": ["d"],
        "е": ["e", "ye"], "ё": ["e", "yo"], "ж": ["zh", "j"], "з": ["z"],
        "и": ["i"],  "й": ["y", "i", "j"], "к": ["k"], "л": ["l"], "м": ["m"],
        "н": ["n"],  "о": ["o"],  "п": ["p"],  "р": ["r"],  "с": ["s"],
        "т": ["t"],  "у": ["u"],  "ф": ["f"],  "х": ["h", "kh", "x"],
        "ц": ["ts", "c"], "ч": ["ch"], "ш": ["sh"], "щ": ["sch", "shch"],
        "ъ": [""],   "ы": ["y", "i"], "ь": [""],  "э": ["e"],
        "ю": ["yu", "iu", "ju"], "я": ["ya", "ia", "ja"]
    ]

    /// Cyrillic sequences that have a shorter Latin spelling than letter-by-letter gives.
    /// Mirrors the "x" -> "кс" entry in `latToCyr`, so "яндекс" reaches "yandex".
    private static let cyrDigraphs: [(pattern: String, options: [String])] = [
        ("кс", ["ks", "x"])
    ]

    private static func cyrillicToLatin(_ s: String) -> [String] {
        let chars = Array(s)
        var results: [String] = [""]
        var i = 0
        while i < chars.count {
            var matched: [String]? = nil
            var step = 1
            for entry in cyrDigraphs {
                let n = entry.pattern.count
                if i + n <= chars.count, String(chars[i..<(i + n)]) == entry.pattern {
                    matched = entry.options
                    step = n
                    break
                }
            }
            let opts = matched ?? cyrToLat[chars[i]] ?? [String(chars[i])]
            var next: [String] = []
            next.reserveCapacity(min(results.count * opts.count, maxVariants))
            outer: for r in results {
                for o in opts {
                    next.append(r + o)
                    if next.count >= maxVariants { break outer }
                }
            }
            results = next
            i += step
        }
        return results
    }

    // MARK: - Latin -> Cyrillic

    /// Multi-letter sequences, longest first: matched greedily before single letters.
    private static let latDigraphs: [(pattern: String, options: [String])] = [
        ("shch", ["щ"]), ("sch", ["щ"]),
        ("zh", ["ж"]), ("kh", ["х"]), ("ch", ["ч"]), ("sh", ["ш"]), ("ts", ["ц"]),
        ("ya", ["я"]), ("yu", ["ю"]), ("yo", ["ё"]), ("ye", ["е"]),
        ("ja", ["я"]), ("ju", ["ю"]), ("jo", ["ё"]),
        ("ia", ["я"]), ("iu", ["ю"])
    ]

    private static let latToCyr: [Character: [String]] = [
        "a": ["а"], "b": ["б"], "c": ["к", "ц", "с"], "d": ["д"], "e": ["е", "э"],
        "f": ["ф"], "g": ["г"], "h": ["х"], "i": ["и"], "j": ["ж", "й"],
        "k": ["к"], "l": ["л"], "m": ["м"], "n": ["н"], "o": ["о"], "p": ["п"],
        "q": ["к"], "r": ["р"], "s": ["с"], "t": ["т"], "u": ["у"], "v": ["в"],
        "w": ["в"], "x": ["кс", "х"], "y": ["й", "ы", "у"], "z": ["з"]
    ]

    private static func latinToCyrillic(_ s: String) -> [String] {
        let chars = Array(s)
        var results: [String] = [""]
        var i = 0
        while i < chars.count {
            var opts: [String]? = nil
            var step = 1
            for entry in latDigraphs {
                let n = entry.pattern.count
                if i + n <= chars.count, String(chars[i..<(i + n)]) == entry.pattern {
                    opts = entry.options
                    step = n
                    break
                }
            }
            let use = opts ?? latToCyr[chars[i]] ?? [String(chars[i])]
            var next: [String] = []
            next.reserveCapacity(min(results.count * use.count, maxVariants))
            outer: for r in results {
                for o in use {
                    next.append(r + o)
                    if next.count >= maxVariants { break outer }
                }
            }
            results = next
            i += step
        }
        return results
    }

    // MARK: - Keyboard layout (ЙЦУКЕН <-> QWERTY, same physical key)

    private static let ruKeyToEnKey: [Character: Character] = [
        "й": "q", "ц": "w", "у": "e", "к": "r", "е": "t", "н": "y", "г": "u",
        "ш": "i", "щ": "o", "з": "p", "х": "[", "ъ": "]",
        "ф": "a", "ы": "s", "в": "d", "а": "f", "п": "g", "р": "h", "о": "j",
        "л": "k", "д": "l", "ж": ";", "э": "'",
        "я": "z", "ч": "x", "с": "c", "м": "v", "и": "b", "т": "n", "ь": "m",
        "б": ",", "ю": ".", "ё": "`"
    ]

    private static let enKeyToRuKey: [Character: Character] = {
        var m: [Character: Character] = [:]
        for (ru, en) in ruKeyToEnKey { m[en] = ru }
        return m
    }()

    /// Re-type the string on the other layout, leaving unmapped characters (digits, dots,
    /// spaces) in place.
    private static func mapKeys(_ s: String, using map: [Character: Character]) -> String {
        String(s.map { map[$0] ?? $0 })
    }
}
