package com.example.analyzer

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import kotlin.math.ln
import kotlin.math.min

enum class StringCategory(val label: String) {
    ALL("All"),
    CLASS_SYMBOL("Classes & Symbols"),
    URL_ENDPOINT("URLs & Paths"),
    SECURITY_KEY("Keys & Config"),
    GENERAL("Strings")
}

data class ExtractedStringItem(
    val offset: Int,
    val offsetHex: String,
    val value: String,
    val category: StringCategory
)

data class HeaderField(
    val name: String,
    val offsetRange: String,
    val rawHex: String,
    val decodedValue: String
)

data class HexDumpRow(
    val offset: Int,
    val offsetHex: String,
    val hexBytes: String,
    val asciiText: String
)

data class YaraSignatureMatch(
    val ruleId: String,
    val title: String,
    val severity: String, // "HIGH", "MEDIUM", "INFO"
    val offsetHex: String,
    val matchedPreview: String,
    val explanationBn: String
)

data class DecodedBinaryStructureItem(
    val typeBadge: String, // "DEX_CLASS", "ELF_SYM", "AXML_TAG", "RES_POOL"
    val name: String,
    val offsetHex: String,
    val detail: String
)

data class BinaryAnalysisResult(
    val sourceName: String,
    val sourcePath: String,
    val totalSizeBytes: Long,
    val analyzedBytesCount: Int,
    val formatName: String,
    val formatBadge: String,
    val magicHex: String,
    val architectureInfo: String,
    val sha256Hash: String,
    val md5Hash: String,
    val overallEntropy: Float,
    val entropyAssessment: String,
    val blockEntropies: List<Float>,
    val nullBytesPercent: Float,
    val printableAsciiPercent: Float,
    val highBytesPercent: Float,
    val headerFields: List<HeaderField>,
    val extractedStrings: List<ExtractedStringItem>,
    val signatureMatches: List<YaraSignatureMatch>,
    val decodedStructures: List<DecodedBinaryStructureItem>,
    val rawSampleBytes: ByteArray
)

object BinaryAnalyzer {

    fun analyzeBytes(
        sourceName: String,
        sourcePath: String,
        fullSizeBytes: Long,
        bytes: ByteArray,
        minStringLength: Int = 5
    ): BinaryAnalysisResult {
        val magicCount = min(bytes.size, 8)
        val magicHex = bytes.take(magicCount).joinToString(" ") { "%02X".format(it) }

        val sha256 = hashBytes(bytes, "SHA-256")
        val md5 = hashBytes(bytes, "MD5")

        val (formatName, formatBadge, archInfo, headerFields) = parseFormatAndHeaders(bytes)

        val overallEntropy = calculateShannonEntropy(bytes, 0, bytes.size)
        val entropyAssessment = when {
            overallEntropy >= 7.2f -> "High Entropy (Compressed / Encrypted / Packed)"
            overallEntropy >= 5.0f -> "Medium-High (Compiled Native / DEX Bytecode)"
            overallEntropy >= 3.2f -> "Moderate (Structured Binary / Symbol Tables)"
            else -> "Low Entropy (Sparse Binary / Plain Text / Padding)"
        }

        val blockCount = 32
        val blockSize = (bytes.size / blockCount).coerceAtLeast(1)
        val blockEntropies = (0 until blockCount).map { idx ->
            val start = idx * blockSize
            val end = if (idx == blockCount - 1) bytes.size else min((idx + 1) * blockSize, bytes.size)
            if (start < end) calculateShannonEntropy(bytes, start, end) else 0f
        }

        var nullCount = 0
        var printableCount = 0
        var highCount = 0
        for (b in bytes) {
            val u = b.toInt() and 0xFF
            when {
                u == 0 -> nullCount++
                u in 0x20..0x7E -> printableCount++
                u >= 0x80 -> highCount++
            }
        }
        val denom = bytes.size.coerceAtLeast(1).toFloat()
        val nullPct = (nullCount / denom) * 100f
        val printablePct = (printableCount / denom) * 100f
        val highPct = (highCount / denom) * 100f

        val extractedStrings = extractStrings(bytes, minStringLength, maxResults = 450)
        val signatureMatches = scanYaraSignatures(bytes, formatBadge, extractedStrings)
        val decodedStructures = decodeFormatStructures(bytes, formatBadge, extractedStrings)

        return BinaryAnalysisResult(
            sourceName = sourceName,
            sourcePath = sourcePath,
            totalSizeBytes = fullSizeBytes,
            analyzedBytesCount = bytes.size,
            formatName = formatName,
            formatBadge = formatBadge,
            magicHex = magicHex,
            architectureInfo = archInfo,
            sha256Hash = sha256,
            md5Hash = md5,
            overallEntropy = overallEntropy,
            entropyAssessment = entropyAssessment,
            blockEntropies = blockEntropies,
            nullBytesPercent = nullPct,
            printableAsciiPercent = printablePct,
            highBytesPercent = highPct,
            headerFields = headerFields,
            extractedStrings = extractedStrings,
            signatureMatches = signatureMatches,
            decodedStructures = decodedStructures,
            rawSampleBytes = bytes.copyOf(min(bytes.size, 65536))
        )
    }

    fun generateHexRows(
        bytes: ByteArray,
        startOffset: Int = 0,
        maxRows: Int = 120,
        searchQuery: String = ""
    ): List<HexDumpRow> {
        val rows = mutableListOf<HexDumpRow>()
        val alignedStart = (startOffset / 16) * 16
        val cleanQuery = searchQuery.trim()
        val hexNeedle = cleanQuery.replace(" ", "").uppercase()
        val isHexSearch = cleanQuery.isNotEmpty() &&
            hexNeedle.length >= 2 &&
            hexNeedle.all { it in '0'..'9' || it in 'A'..'F' }

        var offset = alignedStart.coerceAtLeast(0)
        while (offset < bytes.size && rows.size < maxRows) {
            val end = min(offset + 16, bytes.size)
            val slice = bytes.sliceArray(offset until end)
            val hexStr = slice.joinToString(" ") { "%02X".format(it) }
            val asciiStr = buildString(slice.size) {
                for (b in slice) {
                    val c = b.toInt() and 0xFF
                    append(if (c in 0x20..0x7E) c.toChar() else '.')
                }
            }

            val matches = if (cleanQuery.isEmpty()) {
                true
            } else if (isHexSearch) {
                hexStr.replace(" ", "").contains(hexNeedle) ||
                    asciiStr.contains(cleanQuery, ignoreCase = true)
            } else {
                asciiStr.contains(cleanQuery, ignoreCase = true) ||
                    "%08X".format(offset).contains(cleanQuery, ignoreCase = true)
            }

            if (matches) {
                rows.add(
                    HexDumpRow(
                        offset = offset,
                        offsetHex = "%08X".format(offset),
                        hexBytes = hexStr.padEnd(47, ' '),
                        asciiText = asciiStr
                    )
                )
            }
            offset += 16
        }
        return rows
    }

    private fun scanYaraSignatures(
        bytes: ByteArray,
        formatBadge: String,
        strings: List<ExtractedStringItem>
    ): List<YaraSignatureMatch> {
        val matches = mutableListOf<YaraSignatureMatch>()

        // 1. Check Magic / Container rule
        if (bytes.size >= 4) {
            val mHex = bytes.take(4).joinToString(" ") { "%02X".format(it) }
            when (formatBadge) {
                "DEX" -> matches.add(
                    YaraSignatureMatch(
                        ruleId = "YARA_ANDROID_DEX_HEADER",
                        title = "Dalvik / ART Executable Bytecode (DEX)",
                        severity = "INFO",
                        offsetHex = "0x000000",
                        matchedPreview = "Magic: $mHex (dex\\n)",
                        explanationBn = "এটি অ্যান্ড্রয়েডের মূল কম্পাইল করা কোড ফাইল (classes.dex), যেখানে সব Java/Kotlin ক্লাস ও মেথড থাকে।"
                    )
                )
                "ELF64", "ELF32", "ELF" -> matches.add(
                    YaraSignatureMatch(
                        ruleId = "YARA_NATIVE_ELF_SHARED_OBJECT",
                        title = "Native C/C++ Shared Library (.so / ELF)",
                        severity = "INFO",
                        offsetHex = "0x000000",
                        matchedPreview = "Magic: 7F 45 4C 46 (\\x7FELF)",
                        explanationBn = "এটি প্রসেসরের সরাসরি মেশিন কোডে কম্পাইল করা নেটিভ লাইব্রেরি (ARM64/x86), যা JNI-এর মাধ্যমে কাজ করে।"
                    )
                )
                "AXML" -> matches.add(
                    YaraSignatureMatch(
                        ruleId = "YARA_ANDROID_BINARY_XML",
                        title = "Compiled Android Binary XML (AXML Chunk)",
                        severity = "INFO",
                        offsetHex = "0x000000",
                        matchedPreview = "ResXMLTree_header: 03 00 08 00",
                        explanationBn = "অ্যান্ড্রয়েড অ্যাপ বিল্ড করার সময় সাধারণ XML ফাইলকে এই বাইনারি AXML ফরম্যাটে সংকুচিত করা হয়।"
                    )
                )
            }
        }

        // 2. Scan extracted strings for JNI, Crypto, API Keys, Reflection, Dynamic Loading, URLs
        for (item in strings) {
            val s = item.value
            val lower = s.lowercase()
            when {
                s.contains("Java_") || s.contains("JNI_OnLoad") || s.contains("RegisterNatives") -> {
                    if (matches.count { it.ruleId == "YARA_JNI_BRIDGE_SYMBOL" } < 4) {
                        matches.add(
                            YaraSignatureMatch(
                                ruleId = "YARA_JNI_BRIDGE_SYMBOL",
                                title = "JNI Native Method Bridge Detected",
                                severity = "MEDIUM",
                                offsetHex = item.offsetHex,
                                matchedPreview = s.take(70),
                                explanationBn = "এই সিম্বলটি জাভা/কটলিন কোডের সাথে C/C++ নেটিভ কোডের সংযোগ (JNI Bridge) স্থাপন করে।"
                            )
                        )
                    }
                }

                lower.contains("dexclassloader") || lower.contains("pathclassloader") || lower.contains("inmemorydexclassloader") -> {
                    matches.add(
                        YaraSignatureMatch(
                            ruleId = "YARA_DYNAMIC_CODE_LOADER",
                            title = "Dynamic ClassLoader Reference",
                            severity = "HIGH",
                            offsetHex = item.offsetHex,
                            matchedPreview = s.take(70),
                            explanationBn = "রানটাইমে ডাইনামিক কোড বা ডেক্স লোড করার ক্লাস পাওয়া গেছে, যা প্যাকার বা প্লাগইন সিস্টেমে ব্যবহৃত হয়।"
                        )
                    )
                }

                lower.contains("javax/crypto") || lower.contains("cipher") || lower.contains("messagedigest") || lower.contains("sha-256") || lower.contains("aes") -> {
                    if (matches.count { it.ruleId == "YARA_CRYPTO_PRIMITIVE" } < 4) {
                        matches.add(
                            YaraSignatureMatch(
                                ruleId = "YARA_CRYPTO_PRIMITIVE",
                                title = "Cryptographic / Hashing Primitive",
                                severity = "INFO",
                                offsetHex = item.offsetHex,
                                matchedPreview = s.take(70),
                                explanationBn = "ডেটা এনক্রিপশন, হ্যাশিং (SHA-256/MD5) বা সিকিউরিটি ভেরিফিকেশনের কোড রেফারেন্স।"
                            )
                        )
                    }
                }

                s.startsWith("AIza") || lower.contains("api_key") || lower.contains("apikey") || lower.contains("bearer ") || lower.contains("secret") -> {
                    if (matches.count { it.ruleId == "YARA_CREDENTIAL_OR_KEY_INDICATOR" } < 5) {
                        matches.add(
                            YaraSignatureMatch(
                                ruleId = "YARA_CREDENTIAL_OR_KEY_INDICATOR",
                                title = "API Key / Secret / Auth Token Indicator",
                                severity = "HIGH",
                                offsetHex = item.offsetHex,
                                matchedPreview = s.take(70),
                                explanationBn = "বাইনারির ভেতরে API Key, Secret বা টোকেন জাতীয় স্ট্রিং পাওয়া গেছে; এটি হার্ডকোডেড কি না তা যাচাই করা জরুরি।"
                            )
                        )
                    }
                }

                lower.startsWith("https://") || lower.startsWith("http://") -> {
                    val isCleartext = lower.startsWith("http://") && !lower.contains("schemas.android.com")
                    if (matches.count { it.ruleId.startsWith("YARA_NETWORK_ENDPOINT") } < 5) {
                        matches.add(
                            YaraSignatureMatch(
                                ruleId = if (isCleartext) "YARA_NETWORK_ENDPOINT_CLEARTEXT" else "YARA_NETWORK_ENDPOINT_TLS",
                                title = if (isCleartext) "Cleartext HTTP URL (Unencrypted)" else "Embedded HTTPS Endpoint",
                                severity = if (isCleartext) "HIGH" else "INFO",
                                offsetHex = item.offsetHex,
                                matchedPreview = s.take(70),
                                explanationBn = if (isCleartext) "আন-এনক্রিপ্টেড HTTP লিংক পাওয়া গেছে, যা নেটওয়ার্কে ম্যান-ইন-দ্য-মিডল (MITM) ঝুঁকিতে ফেলতে পারে।"
                                else "বাইনারিতে থাকা নিরাপদ HTTPS সার্ভার বা API এন্ডপয়েন্ট।"
                            )
                        )
                    }
                }
            }
        }

        return matches.distinctBy { "${it.ruleId}_${it.offsetHex}" }.take(25)
    }

    private fun decodeFormatStructures(
        bytes: ByteArray,
        formatBadge: String,
        extractedStrings: List<ExtractedStringItem>
    ): List<DecodedBinaryStructureItem> {
        val items = mutableListOf<DecodedBinaryStructureItem>()

        when (formatBadge) {
            "DEX" -> {
                // Extract Class Descriptors (Lpackage/ClassName;) and Method/Type references
                extractedStrings.filter {
                    (it.value.startsWith("L") && it.value.contains("/") && it.value.endsWith(";")) ||
                        it.category == StringCategory.CLASS_SYMBOL
                }.take(40).forEach { str ->
                    val readableClass = if (str.value.startsWith("L") && str.value.endsWith(";")) {
                        str.value.drop(1).dropLast(1).replace('/', '.')
                    } else str.value
                    items.add(
                        DecodedBinaryStructureItem(
                            typeBadge = "DEX_CLASS",
                            name = readableClass,
                            offsetHex = str.offsetHex,
                            detail = "Raw Descriptor: ${str.value} • DEX String Pool Entry"
                        )
                    )
                }
            }

            "ELF64", "ELF32", "ELF" -> {
                extractedStrings.filter {
                    it.value.endsWith(".so") ||
                        it.value.startsWith("Java_") ||
                        it.value.startsWith("_Z") ||
                        it.value.startsWith(".") ||
                        it.value.startsWith("__")
                }.take(40).forEach { str ->
                    val badge = when {
                        str.value.endsWith(".so") -> "DT_NEEDED"
                        str.value.startsWith("Java_") -> "JNI_EXPORT"
                        str.value.startsWith(".") -> "ELF_SECTION"
                        else -> "DYNSYM"
                    }
                    items.add(
                        DecodedBinaryStructureItem(
                            typeBadge = badge,
                            name = str.value,
                            offsetHex = str.offsetHex,
                            detail = when (badge) {
                                "DT_NEEDED" -> "Dynamic Linker Shared Library Dependency"
                                "JNI_EXPORT" -> "Java Native Interface (JNI) Bridged Function"
                                "ELF_SECTION" -> "ELF Section Table Identifier (.shstrtab)"
                                else -> "Exported/Imported Native Symbol (.dynstr)"
                            }
                        )
                    )
                }
            }

            "AXML" -> {
                // Decode UTF-8 / UTF-16LE strings from AXML string pool to reconstruct Manifest attributes
                val xmlStrings = decodeAxmlReadableStrings(bytes, extractedStrings)
                xmlStrings.forEachIndexed { idx, (offsetHex, tagOrAttr, desc) ->
                    items.add(
                        DecodedBinaryStructureItem(
                            typeBadge = "AXML_NODE #$idx",
                            name = tagOrAttr,
                            offsetHex = offsetHex,
                            detail = desc
                        )
                    )
                }
            }

            else -> {
                extractedStrings.take(30).forEach { str ->
                    items.add(
                        DecodedBinaryStructureItem(
                            typeBadge = str.category.name,
                            name = str.value,
                            offsetHex = str.offsetHex,
                            detail = "Category: ${str.category.label}"
                        )
                    )
                }
            }
        }

        return items
    }

    private fun decodeAxmlReadableStrings(
        bytes: ByteArray,
        asciiStrings: List<ExtractedStringItem>
    ): List<Triple<String, String, String>> {
        val out = mutableListOf<Triple<String, String, String>>()
        // Also scan UTF-16LE characters (common in AXML string pools where every ASCII byte is followed by 0x00)
        val utf16Strings = mutableListOf<Pair<Int, String>>()
        val sb = StringBuilder()
        var startOff = 0
        var i = 0
        while (i + 1 < bytes.size) {
            val b0 = bytes[i].toInt() and 0xFF
            val b1 = bytes[i + 1].toInt() and 0xFF
            if (b0 in 0x20..0x7E && b1 == 0x00) {
                if (sb.isEmpty()) startOff = i
                if (sb.length < 120) sb.append(b0.toChar())
                i += 2
            } else {
                if (sb.length >= 3) {
                    val s = sb.toString().trim()
                    if (isMeaningfulString(s)) {
                        utf16Strings.add(startOff to s)
                    }
                }
                sb.setLength(0)
                i++
            }
        }

        val combined = (asciiStrings.map { it.offset to it.value } + utf16Strings)
            .distinctBy { it.second }
            .take(45)

        for ((off, text) in combined) {
            val role = when {
                text in listOf("manifest", "application", "activity", "service", "receiver", "provider", "uses-permission", "intent-filter", "action", "category", "meta-data") ->
                    "XML Element Tag (<$text>) — ম্যানিফেস্ট এক্সএমএল ট্যাগ"
                text.startsWith("android.permission.") ->
                    "Permission Declaration — অ্যাপের অনুরোধকৃত পারমিশন"
                text.startsWith("android.intent.action.") ->
                    "Intent Action Filter — সিস্টেম বা ইউজার ইভেন্ট অ্যাকশন"
                text.contains("Theme.") || text.startsWith("@style/") ->
                    "UI Theme / Style Resource — অ্যাপের ডিজাইন ও থিম স্টাইল"
                text.startsWith("http://schemas.android.com") ->
                    "Android XML Namespace Schema"
                else ->
                    "AXML String Pool Entry — ম্যানিফেস্ট অ্যাট্রিবিউট বা ভ্যালু"
            }
            out.add(Triple("0x%06X".format(off), text, role))
        }
        return out
    }

    private data class FormatParseOutput(
        val formatName: String,
        val formatBadge: String,
        val archInfo: String,
        val fields: List<HeaderField>
    )

    private fun parseFormatAndHeaders(bytes: ByteArray): FormatParseOutput {
        if (bytes.size >= 4) {
            val b0 = bytes[0].toInt() and 0xFF
            val b1 = bytes[1].toInt() and 0xFF
            val b2 = bytes[2].toInt() and 0xFF
            val b3 = bytes[3].toInt() and 0xFF

            // 1. Dalvik Executable (DEX): "dex\n" -> 64 65 78 0A
            if (b0 == 0x64 && b1 == 0x65 && b2 == 0x78 && b3 == 0x0A) {
                return parseDexHeader(bytes)
            }

            // 2. ELF Native Binary: 7F 'E' 'L' 'F' -> 7F 45 4C 46
            if (b0 == 0x7F && b1 == 0x45 && b2 == 0x4C && b3 == 0x46) {
                return parseElfHeader(bytes)
            }

            // 3. Android Binary XML (AXML): 03 00 08 00
            if (b0 == 0x03 && b1 == 0x00 && b2 == 0x08 && b3 == 0x00) {
                return parseAxmlHeader(bytes)
            }

            // 4. ZIP / APK / JAR Archive: 50 4B 03 04
            if (b0 == 0x50 && b1 == 0x4B && b2 == 0x03 && b3 == 0x04) {
                return parseZipHeader(bytes)
            }

            // 5. Android Resource Table (resources.arsc): 02 00 0C 00
            if (b0 == 0x02 && b1 == 0x00 && b2 == 0x0C && b3 == 0x00) {
                return parseArscHeader(bytes)
            }

            // 6. PNG Image Asset: 89 50 4E 47
            if (b0 == 0x89 && b1 == 0x50 && b2 == 0x4E && b3 == 0x47) {
                return FormatParseOutput(
                    formatName = "PNG Graphic Asset (UI Image)",
                    formatBadge = "PNG",
                    archInfo = "Lossless Raster UI Drawable / Icon Resource",
                    fields = listOf(
                        HeaderField("PNG Signature", "0x00..0x07", "89 50 4E 47 0D 0A 1A 0A", "ISO/IEC 15948 PNG Image Header")
                    )
                )
            }

            // 7. TrueType / OpenType Font: 00 01 00 00 or 'OTTO'
            if ((b0 == 0x00 && b1 == 0x01 && b2 == 0x00 && b3 == 0x00) ||
                (b0 == 0x4F && b1 == 0x54 && b2 == 0x54 && b3 == 0x4F)
            ) {
                return FormatParseOutput(
                    formatName = "Typography Font Asset (TTF / OTF)",
                    formatBadge = "FONT",
                    archInfo = "TrueType / OpenType Vector Font Table",
                    fields = listOf(
                        HeaderField("sfnt Version", "0x00..0x03", "%02X %02X %02X %02X".format(b0, b1, b2, b3), "Font Directory Header")
                    )
                )
            }

            // 8. PE / MZ Executable: 4D 5A
            if (b0 == 0x4D && b1 == 0x5A) {
                return FormatParseOutput(
                    formatName = "Windows PE / MZ Executable",
                    formatBadge = "PE/MZ",
                    archInfo = "x86 / x86_64 Portable Executable",
                    fields = listOf(
                        HeaderField("e_magic", "0x00..0x01", "4D 5A", "MZ (Mark Zbikowski DOS Header)")
                    )
                )
            }
        }

        // Generic Binary / Text fallback
        val previewHex = bytes.take(min(16, bytes.size)).joinToString(" ") { "%02X".format(it) }
        return FormatParseOutput(
            formatName = "Raw Binary / Data Stream",
            formatBadge = "BIN",
            archInfo = "Unstructured or Custom Binary Payload",
            fields = listOf(
                HeaderField("Magic / First 16B", "0x00..0x0F", previewHex, "Raw binary header bytes")
            )
        )
    }

    private fun parseDexHeader(bytes: ByteArray): FormatParseOutput {
        val fields = mutableListOf<HeaderField>()
        val versionStr = if (bytes.size >= 8) {
            String(bytes, 4, 3, Charsets.US_ASCII)
        } else "035"
        fields.add(
            HeaderField(
                name = "DEX Magic & Version",
                offsetRange = "0x00..0x07",
                rawHex = bytes.take(min(8, bytes.size)).joinToString(" ") { "%02X".format(it) },
                decodedValue = "Dalvik Executable v$versionStr"
            )
        )

        if (bytes.size >= 112) {
            val buf = ByteBuffer.wrap(bytes, 0, 112).order(ByteOrder.LITTLE_ENDIAN)
            val checksum = buf.getInt(8).toLong() and 0xFFFFFFFFL
            val sigBytes = bytes.sliceArray(12 until 32)
            val sigHex = sigBytes.joinToString("") { "%02x".format(it) }
            val fileSize = buf.getInt(32).toLong() and 0xFFFFFFFFL
            val headerSize = buf.getInt(36)
            val endianTag = buf.getInt(40)
            val stringIdsSize = buf.getInt(56)
            val stringIdsOff = buf.getInt(60)
            val typeIdsSize = buf.getInt(64)
            val protoIdsSize = buf.getInt(72)
            val fieldIdsSize = buf.getInt(80)
            val methodIdsSize = buf.getInt(88)
            val classDefsSize = buf.getInt(96)
            val dataSize = buf.getInt(104)
            val dataOff = buf.getInt(108)

            fields.add(HeaderField("Adler32 Checksum", "0x08..0x0B", "0x%08X".format(checksum), "Verified Checksum ($checksum)"))
            fields.add(HeaderField("SHA-1 Signature", "0x0C..0x1F", sigHex.take(16) + "…", sigHex))
            fields.add(HeaderField("DEX File Size", "0x20..0x23", "0x%08X".format(fileSize), "$fileSize bytes (Header: $headerSize B)"))
            fields.add(
                HeaderField(
                    "Endianness Tag",
                    "0x28..0x2B",
                    "0x%08X".format(endianTag),
                    if (endianTag == 0x12345678) "ENDIAN_CONSTANT (Little-Endian)" else "REVERSE_ENDIAN"
                )
            )
            fields.add(HeaderField("String IDs Table", "0x38..0x3F", "count=$stringIdsSize", "$stringIdsSize strings @ 0x%06X".format(stringIdsOff)))
            fields.add(HeaderField("Type & Proto IDs", "0x40..0x4F", "types=$typeIdsSize", "$typeIdsSize types • $protoIdsSize method prototypes"))
            fields.add(HeaderField("Field IDs Table", "0x50..0x57", "count=$fieldIdsSize", "$fieldIdsSize fields referenced"))
            fields.add(HeaderField("Method IDs Table", "0x58..0x5F", "count=$methodIdsSize", "$methodIdsSize methods indexed"))
            fields.add(HeaderField("Class Definitions", "0x60..0x67", "count=$classDefsSize", "$classDefsSize compiled classes"))
            fields.add(HeaderField("Data Section", "0x68..0x6F", "size=$dataSize", "$dataSize bytes @ 0x%06X".format(dataOff)))
        }

        return FormatParseOutput(
            formatName = "Dalvik Executable (DEX v$versionStr)",
            formatBadge = "DEX",
            archInfo = "Android Runtime (ART / Dalvik VM) Bytecode",
            fields = fields
        )
    }

    private fun parseElfHeader(bytes: ByteArray): FormatParseOutput {
        val fields = mutableListOf<HeaderField>()
        fields.add(
            HeaderField(
                name = "ELF Magic",
                offsetRange = "0x00..0x03",
                rawHex = "7F 45 4C 46",
                decodedValue = "\\x7FELF (Executable and Linkable Format)"
            )
        )
        if (bytes.size < 64) {
            return FormatParseOutput("Native ELF Binary", "ELF", "Linux / Android Native", fields)
        }

        val eiClass = bytes[4].toInt() and 0xFF
        val is64Bit = eiClass == 2
        val eiData = bytes[5].toInt() and 0xFF
        val isLittleEndian = eiData == 1
        val order = if (isLittleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
        val buf = ByteBuffer.wrap(bytes).order(order)

        val eType = buf.getShort(16).toInt() and 0xFFFF
        val eMachine = buf.getShort(18).toInt() and 0xFFFF

        val typeDesc = when (eType) {
            1 -> "ET_REL (Relocatable Object)"
            2 -> "ET_EXEC (Executable Binary)"
            3 -> "ET_DYN (Shared Object .so / PIE)"
            4 -> "ET_CORE (Core Dump)"
            else -> "Type 0x%04X".format(eType)
        }

        val machineDesc = when (eMachine) {
            0xB7 -> "AArch64 (ARM64-v8a)"
            0x28 -> "ARM (32-bit armeabi-v7a)"
            0x3E -> "x86_64 (AMD64)"
            0x03 -> "Intel 80386 (x86)"
            0xF3 -> "RISC-V"
            else -> "ISA 0x%04X".format(eMachine)
        }

        val entryPoint = if (is64Bit) buf.getLong(24) else (buf.getInt(24).toLong() and 0xFFFFFFFFL)
        val phOff = if (is64Bit) buf.getLong(32) else (buf.getInt(28).toLong() and 0xFFFFFFFFL)
        val shOff = if (is64Bit) buf.getLong(40) else (buf.getInt(32).toLong() and 0xFFFFFFFFL)
        val phNum = if (is64Bit) (buf.getShort(56).toInt() and 0xFFFF) else (buf.getShort(44).toInt() and 0xFFFF)
        val shNum = if (is64Bit) (buf.getShort(60).toInt() and 0xFFFF) else (buf.getShort(48).toInt() and 0xFFFF)

        fields.add(
            HeaderField(
                "ELF Class & Endian",
                "0x04..0x05",
                "%02X %02X".format(eiClass, eiData),
                "${if (is64Bit) "ELF64 (64-bit)" else "ELF32 (32-bit)"} • ${if (isLittleEndian) "Little-Endian (LSB)" else "Big-Endian (MSB)"}"
            )
        )
        fields.add(HeaderField("Object Type (e_type)", "0x10..0x11", "0x%04X".format(eType), typeDesc))
        fields.add(HeaderField("Target ISA (e_machine)", "0x12..0x13", "0x%04X".format(eMachine), machineDesc))
        fields.add(HeaderField("Entry Point (e_entry)", "0x18..0x1F", "0x%08X".format(entryPoint), "Virtual Address 0x%X".format(entryPoint)))
        fields.add(HeaderField("Program Headers", "e_phoff / e_phnum", "count=$phNum", "$phNum segments @ offset 0x%X".format(phOff)))
        fields.add(HeaderField("Section Headers", "e_shoff / e_shnum", "count=$shNum", "$shNum sections @ offset 0x%X".format(shOff)))

        return FormatParseOutput(
            formatName = "ELF ${if (is64Bit) "64-bit" else "32-bit"} Native Binary",
            formatBadge = if (is64Bit) "ELF64" else "ELF32",
            archInfo = "$machineDesc • $typeDesc",
            fields = fields
        )
    }

    private fun parseAxmlHeader(bytes: ByteArray): FormatParseOutput {
        val fields = mutableListOf<HeaderField>()
        fields.add(HeaderField("Chunk Type", "0x00..0x03", "03 00 08 00", "RES_XML_TYPE (Compiled Android Binary XML)"))
        if (bytes.size >= 36) {
            val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val totalSize = buf.getInt(4).toLong() and 0xFFFFFFFFL
            val firstChunkType = buf.getShort(8).toInt() and 0xFFFF
            val stringCount = buf.getInt(16)
            val styleCount = buf.getInt(20)
            val stringsStart = buf.getInt(28)
            fields.add(HeaderField("Document Chunk Size", "0x04..0x07", "0x%08X".format(totalSize), "$totalSize bytes total"))
            fields.add(
                HeaderField(
                    "String Pool Header",
                    "0x08..0x1F",
                    "type=0x%04X".format(firstChunkType),
                    "$stringCount pooled strings ($styleCount styles), data @ 0x%X".format(stringsStart)
                )
            )
        }
        return FormatParseOutput(
            formatName = "Android Compiled Binary XML (AXML)",
            formatBadge = "AXML",
            archInfo = "Android Resource Chunk Hierarchy (ResChunk_header)",
            fields = fields
        )
    }

    private fun parseArscHeader(bytes: ByteArray): FormatParseOutput {
        val fields = mutableListOf<HeaderField>()
        fields.add(HeaderField("Chunk Type", "0x00..0x03", "02 00 0C 00", "RES_TABLE_TYPE (Compiled resources.arsc)"))
        if (bytes.size >= 12) {
            val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val totalSize = buf.getInt(4).toLong() and 0xFFFFFFFFL
            val packageCount = buf.getInt(8)
            fields.add(HeaderField("Table Size", "0x04..0x07", "0x%08X".format(totalSize), "$totalSize bytes"))
            fields.add(HeaderField("Package Count", "0x08..0x0B", "$packageCount", "$packageCount compiled resource package(s)"))
        }
        return FormatParseOutput(
            formatName = "Android Resource Table (ARSC)",
            formatBadge = "ARSC",
            archInfo = "Compiled Resource IDs & String Pools",
            fields = fields
        )
    }

    private fun parseZipHeader(bytes: ByteArray): FormatParseOutput {
        val fields = mutableListOf<HeaderField>()
        fields.add(HeaderField("Local File Signature", "0x00..0x03", "50 4B 03 04", "PK\\x03\\x04 (ZIP / APK Container)"))
        if (bytes.size >= 30) {
            val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val versionNeeded = buf.getShort(4).toInt() and 0xFFFF
            val compression = buf.getShort(8).toInt() and 0xFFFF
            val crc32 = buf.getInt(14).toLong() and 0xFFFFFFFFL
            val compSize = buf.getInt(18).toLong() and 0xFFFFFFFFL
            val uncompSize = buf.getInt(22).toLong() and 0xFFFFFFFFL
            val nameLen = buf.getShort(26).toInt() and 0xFFFF
            val firstEntryName = if (nameLen in 1..120 && bytes.size >= 30 + nameLen) {
                String(bytes, 30, nameLen, Charsets.UTF_8)
            } else "N/A"
            fields.add(HeaderField("ZIP Version & Method", "0x04..0x09", "v$versionNeeded / m=$compression", if (compression == 8) "DEFLATE Compressed" else "STORED (Uncompressed)"))
            fields.add(HeaderField("First Entry CRC32", "0x0E..0x19", "0x%08X".format(crc32), "Compressed: $compSize B / Raw: $uncompSize B"))
            fields.add(HeaderField("First Archive Entry", "0x1E..", firstEntryName, "Entry: $firstEntryName"))
        }
        return FormatParseOutput(
            formatName = "APK / ZIP Archive Container",
            formatBadge = "APK/ZIP",
            archInfo = "Android Package Archive / PKZIP",
            fields = fields
        )
    }

    fun calculateShannonEntropy(bytes: ByteArray, start: Int, end: Int): Float {
        val len = end - start
        if (len <= 0) return 0f
        val counts = IntArray(256)
        for (i in start until end) {
            counts[bytes[i].toInt() and 0xFF]++
        }
        var entropy = 0.0
        val invLen = 1.0 / len.toDouble()
        val invLn2 = 1.0 / ln(2.0)
        for (c in counts) {
            if (c > 0) {
                val p = c * invLen
                entropy -= p * ln(p) * invLn2
            }
        }
        return entropy.toFloat().coerceIn(0f, 8f)
    }

    private fun extractStrings(
        bytes: ByteArray,
        minLength: Int,
        maxResults: Int
    ): List<ExtractedStringItem> {
        val results = mutableListOf<ExtractedStringItem>()
        val sb = StringBuilder()
        var currentStartOffset = 0

        for (i in bytes.indices) {
            val b = bytes[i].toInt() and 0xFF
            if (b in 0x20..0x7E) {
                if (sb.isEmpty()) currentStartOffset = i
                if (sb.length < 180) {
                    sb.append(b.toChar())
                }
            } else {
                if (sb.length >= minLength) {
                    val str = sb.toString().trim()
                    if (str.length >= minLength && isMeaningfulString(str)) {
                        results.add(
                            ExtractedStringItem(
                                offset = currentStartOffset,
                                offsetHex = "0x%06X".format(currentStartOffset),
                                value = str,
                                category = classifyString(str)
                            )
                        )
                        if (results.size >= maxResults) break
                    }
                }
                sb.setLength(0)
            }
        }
        return results
    }

    private fun isMeaningfulString(str: String): Boolean {
        var alnum = 0
        for (c in str) {
            if (c.isLetterOrDigit()) alnum++
        }
        return alnum >= 3 && (alnum.toFloat() / str.length) >= 0.45f
    }

    private fun classifyString(str: String): StringCategory {
        val lower = str.lowercase()
        return when {
            lower.startsWith("http://") ||
                lower.startsWith("https://") ||
                lower.startsWith("ws://") ||
                lower.startsWith("wss://") ||
                lower.contains("/api/") ||
                lower.contains(".com/") ||
                lower.contains("/system/") ||
                lower.endsWith(".so") ||
                lower.endsWith(".dex") ||
                lower.endsWith(".apk") -> StringCategory.URL_ENDPOINT

            (str.startsWith("L") && str.contains("/") && str.endsWith(";")) ||
                str.startsWith("Java_") ||
                str.startsWith("_Z") ||
                lower.startsWith("androidx.") ||
                lower.startsWith("kotlin.") ||
                lower.startsWith("com.") ||
                lower.startsWith("java.") ||
                lower.contains("libc.") ||
                lower.contains("__cxa_") -> StringCategory.CLASS_SYMBOL

            lower.contains("secret") ||
                lower.contains("token") ||
                lower.contains("apikey") ||
                lower.contains("api_key") ||
                lower.contains("bearer") ||
                lower.contains("sha256") ||
                lower.contains("permission.") ||
                lower.contains("signature") ||
                lower.contains("cipher") ||
                lower.contains("ssl") -> StringCategory.SECURITY_KEY

            else -> StringCategory.GENERAL
        }
    }

    private fun hashBytes(bytes: ByteArray, algorithm: String): String {
        return try {
            val digest = MessageDigest.getInstance(algorithm).digest(bytes)
            digest.joinToString("") { "%02x".format(it) }
        } catch (_: Exception) {
            "unavailable"
        }
    }
}
