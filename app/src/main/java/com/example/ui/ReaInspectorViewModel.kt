package com.example.ui

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.example.analyzer.ApkAuditReport
import com.example.analyzer.ApkPackageInspector
import com.example.analyzer.BinaryAnalysisResult
import com.example.analyzer.BinaryAnalyzer
import com.example.analyzer.BinaryTargetPreset
import com.example.analyzer.HexDumpRow
import com.example.analyzer.InstalledPackageBrief
import com.example.analyzer.StringCategory
import com.example.analyzer.WebBehaviorTracer
import com.example.analyzer.WebTraceResult
import com.example.data.EvidenceDatabase
import com.example.data.EvidenceReportEntity
import com.example.data.EvidenceRepository
import com.google.firebase.Firebase
import com.google.firebase.ai.ai
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import kotlin.math.min

private const val TAG = "ReaInspectorVM"

enum class ReaMainTab(val route: String, val title: String, val bnSubtitle: String) {
    BINARY("binary_inspector", "Binary & Hex", "বাইনারি ও হেক্স বিশ্লেষণ"),
    APK("apk_forensics", "APK & Design", "APK-এর সকল তথ্য, ডিজাইন ও কপি"),
    WEB("web_tracer", "Web & API", "ওয়েব ও নেটওয়ার্ক ট্রেস"),
    AI("ai_analyst", "AI Explainer", "এআই ফরেনসিক সহকারী (কোনটার কাজ কী)"),
    VAULT("evidence_vault", "Vault", "প্রমাণ ও রিপোর্ট ভল্ট")
}

sealed interface AiAnalystUiState {
    data object Idle : AiAnalystUiState
    data object Loading : AiAnalystUiState
    data class Streaming(val partialText: String) : AiAnalystUiState
    data class Success(val fullText: String) : AiAnalystUiState
    data class Error(val errorMessage: String) : AiAnalystUiState
}

data class AiChatEntry(
    val id: Long = System.currentTimeMillis(),
    val userPrompt: String,
    val contextLabel: String,
    val aiResponse: String
)

data class ReaUiState(
    val currentTab: ReaMainTab = ReaMainTab.BINARY,
    val binaryPresets: List<BinaryTargetPreset> = emptyList(),
    val selectedPresetId: String = "self_dex",
    val isLoadingBinary: Boolean = false,
    val binaryResult: BinaryAnalysisResult? = null,
    val binarySubTab: Int = 0, // 0=Headers, 1=Hex Dump, 2=Strings, 3=YARA & Decoded, 4=Entropy
    val minStringLength: Int = 5,
    val selectedStringCategory: StringCategory = StringCategory.ALL,
    val stringSearchQuery: String = "",
    val hexSearchQuery: String = "",
    val hexStartOffset: Int = 0,
    val currentHexRows: List<HexDumpRow> = emptyList(),

    // APK & Package Audit + Design Profile
    val inspectablePackages: List<InstalledPackageBrief> = emptyList(),
    val selectedPackageName: String = "",
    val apkAuditReport: ApkAuditReport? = null,
    val isLoadingApk: Boolean = false,
    val apkSubTab: Int = 0, // 0=Overview & Cert, 1=UI & Design, 2=Archive, 3=Permissions, 4=Components, 5=DEX Header

    // Web & API Tracer
    val targetUrlInput: String = "https://api.github.com/repos/morluto/rea",
    val webRequestMethod: String = "GET",
    val webCustomHeaders: String = "",
    val webRequestBody: String = "",
    val showWebAdvancedBuilder: Boolean = false,
    val isTracingUrl: Boolean = false,
    val webTraceResult: WebTraceResult? = null,
    val webSubTab: Int = 0, // 0=Security & Headers, 1=TLS Certs & Endpoints, 2=Payload Preview, 3=Replay Code

    // AI Forensic Explainer (Firebase AI Logic - Gemini)
    val aiPromptInput: String = "",
    val aiState: AiAnalystUiState = AiAnalystUiState.Idle,
    val aiActiveTopic: String = "Current APK, Binary & Web Telemetry",
    val aiHistory: List<AiChatEntry> = emptyList(),

    // Vault filter & feedback
    val vaultCategoryFilter: String = "ALL",
    val vaultSearchQuery: String = "",
    val selectedEvidenceReport: EvidenceReportEntity? = null,
    val statusBannerMessage: String? = null
)

class ReaInspectorViewModel(
    private val appContext: Context,
    private val repository: EvidenceRepository
) : ViewModel() {

    // Lazy initialization of Gemini 3.8 Flash via Firebase AI Logic as mandated by skill
    private val geminiModel by lazy {
        Firebase.ai.generativeModel("gemini-3.8-flash")
    }

    private val _uiState = MutableStateFlow(ReaUiState())
    val uiState: StateFlow<ReaUiState> = _uiState.asStateFlow()

    val savedReports: StateFlow<List<EvidenceReportEntity>> = repository.allReports
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = emptyList()
        )

    init {
        initializeToolkit()
    }

    private fun initializeToolkit() {
        viewModelScope.launch(Dispatchers.IO) {
            val presets = ApkPackageInspector.getBuiltInTargets(appContext)
            val packages = ApkPackageInspector.listInspectablePackages(appContext)
            val initialBinary = ApkPackageInspector.loadPresetBinary(appContext, "self_dex", 5)
            val initialHex = BinaryAnalyzer.generateHexRows(initialBinary.rawSampleBytes, 0, 100, "")
            val initialApkAudit = ApkPackageInspector.inspectPackage(appContext, appContext.packageName)

            _uiState.update { state ->
                state.copy(
                    binaryPresets = presets,
                    selectedPresetId = "self_dex",
                    binaryResult = initialBinary,
                    currentHexRows = initialHex,
                    inspectablePackages = packages,
                    selectedPackageName = appContext.packageName,
                    apkAuditReport = initialApkAudit
                )
            }

            if (repository.getCount() == 0) {
                seedInitialEvidence(initialBinary, initialApkAudit)
            }

            runWebTrace("https://api.github.com/repos/morluto/rea")
        }
    }

    private suspend fun seedInitialEvidence(
        dexBinary: BinaryAnalysisResult,
        apkAudit: ApkAuditReport
    ) {
        val dexFindings = buildString {
            appendLine("• Target: ${dexBinary.sourceName}")
            appendLine("• Format: ${dexBinary.formatName} (${dexBinary.magicHex})")
            appendLine("• SHA-256: ${dexBinary.sha256Hash}")
            appendLine("• Shannon Entropy: ${"%.2f".format(dexBinary.overallEntropy)} bits/byte (${dexBinary.entropyAssessment})")
            appendLine("• YARA Signatures Matched: ${dexBinary.signatureMatches.size}")
            dexBinary.headerFields.forEach { field ->
                appendLine("• ${field.name} [${field.offsetRange}]: ${field.decodedValue}")
            }
        }
        repository.insert(
            EvidenceReportEntity(
                title = "Self APK: classes.dex Bytecode Dissection",
                category = "DEX_BINARY",
                magicFormat = "${dexBinary.formatBadge} • ${dexBinary.magicHex}",
                summaryMetrics = "Entropy ${"%.2f".format(dexBinary.overallEntropy)} b/B • ${dexBinary.extractedStrings.size} Strings • ${dexBinary.signatureMatches.size} YARA",
                detailedEvidence = dexFindings,
                engineerNotes = "Auto-captured live Dalvik Executable header, YARA signatures & string table evidence from running APK.",
                isPinned = true
            )
        )

        val apkFindings = buildString {
            appendLine("• Package: ${apkAudit.packageName} (v${apkAudit.versionName})")
            appendLine("• Security Score: ${apkAudit.securityScore}/100 (${apkAudit.securityGrade})")
            appendLine("• Primary UI / Design System: ${apkAudit.designProfile.primaryUiFramework}")
            appendLine("• Tech Stack: ${apkAudit.designProfile.detectedTechStack.joinToString()}")
            appendLine("• SDK Target: minSdk ${apkAudit.minSdk} / targetSdk ${apkAudit.targetSdk}")
            appendLine("• Archive Entries: ${apkAudit.totalArchiveEntries} files (${apkAudit.dexCount} DEX, ${apkAudit.nativeSoCount} Native .so)")
            appendLine("• Certificate SHA-256: ${apkAudit.certSha256}")
            appendLine("• Certificate Issuer: ${apkAudit.certDetails.issuerDn}")
            appendLine("• Declared Components: ${apkAudit.components.size} (${apkAudit.components.count { it.isExported }} exported)")
            appendLine("• Requested Permissions: ${apkAudit.permissions.joinToString { it.shortName }}")
        }
        repository.insert(
            EvidenceReportEntity(
                title = "APK Security, Design & Manifest Audit (${apkAudit.appLabel})",
                category = "APK_AUDIT",
                magicFormat = "APK • Score ${apkAudit.securityScore}/100 • ${apkAudit.designProfile.primaryUiFramework}",
                summaryMetrics = "${apkAudit.totalArchiveEntries} Entries • ${apkAudit.permissions.size} Perms • ${apkAudit.components.size} Components",
                detailedEvidence = apkFindings,
                engineerNotes = "Baseline package manifest, UI design profile, signing certificate, and exported component surface audit.",
                isPinned = false
            )
        )
    }

    fun selectMainTab(tab: ReaMainTab) {
        _uiState.update { it.copy(currentTab = tab, selectedEvidenceReport = null) }
    }

    fun selectBinarySubTab(index: Int) {
        _uiState.update { it.copy(binarySubTab = index) }
    }

    fun selectApkSubTab(index: Int) {
        _uiState.update { it.copy(apkSubTab = index) }
    }

    fun selectWebSubTab(index: Int) {
        _uiState.update { it.copy(webSubTab = index) }
    }

    fun selectBinaryPreset(presetId: String) {
        _uiState.update { it.copy(selectedPresetId = presetId, isLoadingBinary = true, hexStartOffset = 0) }
        viewModelScope.launch(Dispatchers.IO) {
            val minLen = _uiState.value.minStringLength
            val result = ApkPackageInspector.loadPresetBinary(appContext, presetId, minLen)
            val hexRows = BinaryAnalyzer.generateHexRows(result.rawSampleBytes, 0, 100, _uiState.value.hexSearchQuery)
            _uiState.update {
                it.copy(
                    isLoadingBinary = false,
                    binaryResult = result,
                    currentHexRows = hexRows
                )
            }
        }
    }

    fun inspectExternalUri(uri: Uri) {
        _uiState.update { it.copy(isLoadingBinary = true, selectedPresetId = "custom_uri", hexStartOffset = 0) }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val cr = appContext.contentResolver
                var displayName = uri.lastPathSegment ?: "external_binary.bin"
                var fileSize = 0L
                cr.query(uri, null, null, null, null)?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
                        if (nameIdx >= 0) displayName = cursor.getString(nameIdx) ?: displayName
                        if (sizeIdx >= 0) fileSize = cursor.getLong(sizeIdx)
                    }
                }

                val bytes = cr.openInputStream(uri)?.use { stream ->
                    val out = java.io.ByteArrayOutputStream()
                    val buf = ByteArray(8192)
                    var total = 0
                    val maxRead = 96 * 1024
                    while (total < maxRead) {
                        val r = stream.read(buf, 0, min(buf.size, maxRead - total))
                        if (r <= 0) break
                        out.write(buf, 0, r)
                        total += r
                    }
                    out.toByteArray()
                } ?: ByteArray(0)

                val minLen = _uiState.value.minStringLength
                val result = BinaryAnalyzer.analyzeBytes(
                    sourceName = displayName,
                    sourcePath = uri.toString(),
                    fullSizeBytes = if (fileSize > 0) fileSize else bytes.size.toLong(),
                    bytes = bytes,
                    minStringLength = minLen
                )
                val hexRows = BinaryAnalyzer.generateHexRows(result.rawSampleBytes, 0, 100, "")
                _uiState.update {
                    it.copy(
                        isLoadingBinary = false,
                        binaryResult = result,
                        currentHexRows = hexRows,
                        statusBannerMessage = "Loaded $displayName (${bytes.size} bytes analyzed)"
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isLoadingBinary = false,
                        statusBannerMessage = "Failed to read file: ${e.localizedMessage}"
                    )
                }
            }
        }
    }

    fun inspectExternalApkFromStorage(uri: Uri) {
        _uiState.update { it.copy(isLoadingApk = true, selectedPackageName = "external_apk") }
        viewModelScope.launch(Dispatchers.IO) {
            val report = ApkPackageInspector.inspectExternalApkUri(appContext, uri)
            if (report != null) {
                _uiState.update {
                    it.copy(
                        isLoadingApk = false,
                        apkAuditReport = report,
                        statusBannerMessage = "Loaded external APK: ${report.appLabel} (${report.packageName})"
                    )
                }
            } else {
                _uiState.update {
                    it.copy(
                        isLoadingApk = false,
                        statusBannerMessage = "Could not parse selected file as an Android APK archive."
                    )
                }
            }
        }
    }

    fun exportApkCopyToUri(destinationUri: Uri) {
        val currentApk = _uiState.value.apkAuditReport ?: return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val bytesCopied = appContext.contentResolver.openOutputStream(destinationUri)?.use { out ->
                    ApkPackageInspector.exportApkCopyToStream(currentApk.sourceApkPath, out)
                } ?: -1L

                withContext(Dispatchers.Main) {
                    if (bytesCopied > 0) {
                        _uiState.update {
                            it.copy(
                                statusBannerMessage = "APK কপি সফলভাবে সেভ হয়েছে! (${bytesCopied / 1024} KB — ${currentApk.appLabel})"
                            )
                        }
                    } else {
                        _uiState.update {
                            it.copy(statusBannerMessage = "APK কপি তৈরি করা যায়নি: সোর্স ফাইল অ্যাক্সেস সীমাবদ্ধ।")
                        }
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    _uiState.update {
                        it.copy(statusBannerMessage = "APK Export Error: ${e.localizedMessage}")
                    }
                }
            }
        }
    }

    fun exportEvidenceReportToUri(report: EvidenceReportEntity, destinationUri: Uri, asJson: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val payload = if (asJson) {
                    JSONObject().apply {
                        put("id", report.id)
                        put("title", report.title)
                        put("category", report.category)
                        put("magicFormat", report.magicFormat)
                        put("summaryMetrics", report.summaryMetrics)
                        put("detailedEvidence", report.detailedEvidence)
                        put("engineerNotes", report.engineerNotes)
                        put("timestamp", report.timestamp)
                    }.toString(2)
                } else {
                    buildString {
                        appendLine("# ${report.title}")
                        appendLine("- **Category:** ${report.category}")
                        appendLine("- **Format / Signature:** ${report.magicFormat}")
                        appendLine("- **Metrics:** ${report.summaryMetrics}")
                        appendLine("\n## Hard Forensic Evidence")
                        appendLine(report.detailedEvidence)
                        if (report.engineerNotes.isNotBlank()) {
                            appendLine("\n## Engineer Notes")
                            appendLine(report.engineerNotes)
                        }
                    }
                }
                appContext.contentResolver.openOutputStream(destinationUri)?.use { out ->
                    out.write(payload.toByteArray(Charsets.UTF_8))
                }
                withContext(Dispatchers.Main) {
                    _uiState.update {
                        it.copy(statusBannerMessage = "Report exported as ${if (asJson) "JSON" else "Markdown"} successfully!")
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    _uiState.update {
                        it.copy(statusBannerMessage = "Export failed: ${e.localizedMessage}")
                    }
                }
            }
        }
    }

    fun updateMinStringLength(length: Int) {
        val currentPreset = _uiState.value.selectedPresetId
        _uiState.update { it.copy(minStringLength = length) }
        if (currentPreset != "custom_uri") {
            selectBinaryPreset(currentPreset)
        } else {
            val currentBytes = _uiState.value.binaryResult?.rawSampleBytes ?: return
            val currentRes = _uiState.value.binaryResult ?: return
            viewModelScope.launch(Dispatchers.Default) {
                val updated = BinaryAnalyzer.analyzeBytes(
                    sourceName = currentRes.sourceName,
                    sourcePath = currentRes.sourcePath,
                    fullSizeBytes = currentRes.totalSizeBytes,
                    bytes = currentBytes,
                    minStringLength = length
                )
                _uiState.update { it.copy(binaryResult = updated) }
            }
        }
    }

    fun updateStringCategory(category: StringCategory) {
        _uiState.update { it.copy(selectedStringCategory = category) }
    }

    fun updateStringSearchQuery(query: String) {
        _uiState.update { it.copy(stringSearchQuery = query) }
    }

    fun updateHexSearchAndOffset(query: String = _uiState.value.hexSearchQuery, offset: Int = _uiState.value.hexStartOffset) {
        val sample = _uiState.value.binaryResult?.rawSampleBytes ?: return
        val clampedOffset = offset.coerceIn(0, (sample.size - 16).coerceAtLeast(0))
        _uiState.update { it.copy(hexSearchQuery = query, hexStartOffset = clampedOffset) }
        viewModelScope.launch(Dispatchers.Default) {
            val rows = BinaryAnalyzer.generateHexRows(sample, clampedOffset, 100, query)
            _uiState.update { it.copy(currentHexRows = rows) }
        }
    }

    fun selectPackageForAudit(packageName: String) {
        _uiState.update { it.copy(selectedPackageName = packageName, isLoadingApk = true) }
        viewModelScope.launch(Dispatchers.IO) {
            val report = ApkPackageInspector.inspectPackage(appContext, packageName)
            _uiState.update { it.copy(apkAuditReport = report, isLoadingApk = false) }
        }
    }

    fun updateTargetUrlInput(url: String) {
        _uiState.update { it.copy(targetUrlInput = url) }
    }

    fun updateWebMethod(method: String) {
        _uiState.update { it.copy(webRequestMethod = method) }
    }

    fun updateWebCustomHeaders(headers: String) {
        _uiState.update { it.copy(webCustomHeaders = headers) }
    }

    fun updateWebRequestBody(body: String) {
        _uiState.update { it.copy(webRequestBody = body) }
    }

    fun toggleWebAdvancedBuilder() {
        _uiState.update { it.copy(showWebAdvancedBuilder = !it.showWebAdvancedBuilder) }
    }

    fun runWebTrace(urlToTrace: String = _uiState.value.targetUrlInput) {
        if (urlToTrace.isBlank()) return
        val state = _uiState.value
        _uiState.update { it.copy(targetUrlInput = urlToTrace, isTracingUrl = true) }
        viewModelScope.launch {
            val result = WebBehaviorTracer.traceUrl(
                rawUrl = urlToTrace,
                method = state.webRequestMethod,
                customHeadersText = state.webCustomHeaders,
                requestBodyText = state.webRequestBody
            )
            _uiState.update {
                it.copy(
                    isTracingUrl = false,
                    webTraceResult = result
                )
            }
        }
    }

    // --- AI Forensic Analyst (Gemini 3.8 Flash via Firebase AI Logic) ---

    fun updateAiPromptInput(text: String) {
        _uiState.update { it.copy(aiPromptInput = text) }
    }

    fun explainWithAiAndNavigate(topicTitle: String, userQuestion: String, specificContext: String? = null) {
        _uiState.update {
            it.copy(
                currentTab = ReaMainTab.AI,
                aiActiveTopic = topicTitle,
                aiPromptInput = userQuestion
            )
        }
        askAiForensicAnalyst(userQuestion, topicTitle, specificContext)
    }

    fun askAiForensicAnalyst(
        userPrompt: String = _uiState.value.aiPromptInput,
        topicTitle: String = _uiState.value.aiActiveTopic,
        specificContext: String? = null
    ) {
        val cleanPrompt = userPrompt.trim()
        if (cleanPrompt.isEmpty()) return

        val forensicSnapshot = specificContext ?: buildLiveForensicSnapshot()
        val fullPrompt = buildString {
            appendLine("You are the built-in AI Forensic & Reverse Engineering Explainer inside the Android app 'REA Inspector'.")
            appendLine("Always answer clearly in Bengali (বাংলা) with helpful technical terms in English so the user easily understands what every file, header, permission, UI/Design asset, or network trace does.")
            appendLine("Structure your explanation with short headings and bullet points:")
            appendLine("1. এটার কাজ কী? (What is it & how does it work?)")
            appendLine("2. APK / বাইনারি ও ডিজাইন বিশ্লেষণ (Technical, UI/Design & Architecture Breakdown)")
            appendLine("3. সিকিউরিটি ও পরামর্শ (Security Posture & Practical Takeaways)")
            appendLine()
            appendLine("--- LIVE CAPTURED FORENSIC CONTEXT ($topicTitle) ---")
            appendLine(forensicSnapshot)
            appendLine()
            appendLine("--- USER QUESTION ---")
            appendLine(cleanPrompt)
        }

        _uiState.update {
            it.copy(
                aiState = AiAnalystUiState.Loading,
                aiActiveTopic = topicTitle
            )
        }

        viewModelScope.launch {
            val accumulatedText = StringBuilder()
            try {
                withTimeout(60_000L) {
                    geminiModel.generateContentStream(fullPrompt).collect { chunk ->
                        val chunkText = chunk.text.orEmpty()
                        accumulatedText.append(chunkText)
                        _uiState.update {
                            it.copy(aiState = AiAnalystUiState.Streaming(accumulatedText.toString()))
                        }
                    }
                }
                val finalOutput = accumulatedText.toString().trim()
                if (finalOutput.isNotEmpty()) {
                    val newEntry = AiChatEntry(
                        userPrompt = cleanPrompt,
                        contextLabel = topicTitle,
                        aiResponse = finalOutput
                    )
                    _uiState.update { state ->
                        state.copy(
                            aiState = AiAnalystUiState.Success(finalOutput),
                            aiPromptInput = "",
                            aiHistory = listOf(newEntry) + state.aiHistory.take(14)
                        )
                    }
                } else {
                    _uiState.update {
                        it.copy(aiState = AiAnalystUiState.Error("AI returned an empty response. Please try again."))
                    }
                }
            } catch (e: TimeoutCancellationException) {
                Log.e(TAG, "AI explanation timed out after 60s", e)
                _uiState.update {
                    it.copy(
                        aiState = AiAnalystUiState.Error("AI analysis timed out after 60 seconds. Please try again.")
                    )
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Firebase AI generation failed", e)
                _uiState.update {
                    it.copy(
                        aiState = AiAnalystUiState.Error(e.localizedMessage ?: "AI analysis failed.")
                    )
                }
            }
        }
    }

    private fun buildLiveForensicSnapshot(): String {
        val state = _uiState.value
        val bin = state.binaryResult
        val apk = state.apkAuditReport
        val web = state.webTraceResult

        return buildString {
            if (apk != null) {
                appendLine("[CURRENT APK AUDIT & DESIGN PROFILE]")
                appendLine("App: ${apk.appLabel} (${apk.packageName}) v${apk.versionName} (code ${apk.versionCode})")
                appendLine("SDK: minSdk=${apk.minSdk}, targetSdk=${apk.targetSdk} | Debuggable=${apk.isDebuggable} | Size=${apk.apkSizeBytes / 1024} KB")
                appendLine("Security Score: ${apk.securityScore}/100 (${apk.securityGrade})")
                appendLine("UI & Design Framework: ${apk.designProfile.primaryUiFramework}")
                appendLine("Tech Stack: ${apk.designProfile.detectedTechStack.joinToString()}")
                appendLine("UI Assets: Layouts=${apk.designProfile.layoutXmlCount}, Drawables=${apk.designProfile.drawableAssetCount}, Fonts=${apk.designProfile.fontAssetCount} (${apk.designProfile.fontFiles.joinToString()}), Mipmaps=${apk.designProfile.mipmapIconCount}, Raw Assets=${apk.designProfile.rawAssetCount}")
                appendLine("Certificate: Issuer=${apk.certDetails.issuerDn}, Alg=${apk.certDetails.sigAlgName}, Valid=${apk.certDetails.validFrom}..${apk.certDetails.validUntil}, SHA256=${apk.certSha256}")
                appendLine("Permissions (${apk.permissions.size}): ${apk.permissions.joinToString { it.shortName }}")
                appendLine("Components (${apk.components.size}): ${apk.components.take(10).joinToString { "${it.type}:${it.name.substringAfterLast('.')}(exported=${it.isExported})" }}")
                appendLine()
            }
            if (bin != null) {
                appendLine("[CURRENT BINARY & HEX DISSECTION]")
                appendLine("Source: ${bin.sourceName} (${bin.formatName}, Magic=${bin.magicHex})")
                appendLine("Architecture: ${bin.architectureInfo} | Entropy: ${"%.2f".format(bin.overallEntropy)}/8.0 (${bin.entropyAssessment})")
                appendLine("Headers: ${bin.headerFields.joinToString { "${it.name}=${it.decodedValue}" }}")
                appendLine("YARA Matches: ${bin.signatureMatches.joinToString { "${it.title}(${it.severity})" }}")
                appendLine("Sample Strings: ${bin.extractedStrings.take(12).joinToString { it.value }}")
                appendLine()
            }
            if (web != null) {
                appendLine("[CURRENT WEB & API TRACE]")
                appendLine("URL: ${web.requestMethod} ${web.finalUrl} -> Status ${web.statusCode} (${web.protocol}, ${web.tlsVersion}, ${web.cipherSuite})")
                appendLine("Timing: DNS=${web.dnsDurationMs}ms, TCP=${web.connectDurationMs}ms, TLS=${web.tlsDurationMs}ms, Total=${web.totalDurationMs}ms")
                appendLine("Security Headers: ${web.securityAudit.joinToString { "${it.headerName}:${if (it.isPresent) "OK" else "MISSING"}" }}")
            }
        }
    }

    fun saveCurrentBinaryEvidence() {
        val bin = _uiState.value.binaryResult ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val category = if (bin.formatBadge.contains("ELF")) "ELF_NATIVE" else "DEX_BINARY"
            val details = buildString {
                appendLine("• Binary Source: ${bin.sourceName}")
                appendLine("• Path: ${bin.sourcePath}")
                appendLine("• Format & Magic: ${bin.formatName} [${bin.magicHex}]")
                appendLine("• Architecture: ${bin.architectureInfo}")
                appendLine("• SHA-256: ${bin.sha256Hash}")
                appendLine("• MD5: ${bin.md5Hash}")
                appendLine("• Entropy: ${"%.2f".format(bin.overallEntropy)} bits/B (${bin.entropyAssessment})")
                appendLine("• Byte Distribution: Printable ${"%.1f".format(bin.printableAsciiPercent)}% | Null ${"%.1f".format(bin.nullBytesPercent)}% | High ${"%.1f".format(bin.highBytesPercent)}%")
                appendLine("\n--- YARA & Security Signatures (${bin.signatureMatches.size}) ---")
                bin.signatureMatches.forEach { m ->
                    appendLine("• [${m.severity}] ${m.title} @ ${m.offsetHex}: ${m.matchedPreview}")
                }
                appendLine("\n--- Parsed Header Fields ---")
                bin.headerFields.forEach { f ->
                    appendLine("• ${f.name} (${f.offsetRange}): ${f.decodedValue} [${f.rawHex}]")
                }
                appendLine("\n--- Top Extracted Symbols & Strings ---")
                bin.extractedStrings.take(15).forEach { s ->
                    appendLine("  ${s.offsetHex} [${s.category.label}] ${s.value}")
                }
            }
            repository.insert(
                EvidenceReportEntity(
                    title = "Binary Analysis: ${bin.sourceName}",
                    category = category,
                    magicFormat = "${bin.formatBadge} • ${bin.magicHex}",
                    summaryMetrics = "Entropy ${"%.2f".format(bin.overallEntropy)} b/B • ${bin.extractedStrings.size} Strings • ${bin.signatureMatches.size} YARA",
                    detailedEvidence = details,
                    engineerNotes = "Captured from Binary & Hex Dissector."
                )
            )
            withContext(Dispatchers.Main) {
                _uiState.update { it.copy(statusBannerMessage = "Saved '${bin.sourceName}' to Evidence Vault") }
            }
        }
    }

    fun saveCurrentApkEvidence() {
        val apk = _uiState.value.apkAuditReport ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val details = buildString {
                appendLine("• App Name: ${apk.appLabel} (${apk.packageName})")
                appendLine("• Version: ${apk.versionName} (Code ${apk.versionCode})")
                appendLine("• Security Score: ${apk.securityScore}/100 (${apk.securityGrade})")
                appendLine("• Primary UI Framework: ${apk.designProfile.primaryUiFramework}")
                appendLine("• Detected Tech Stack: ${apk.designProfile.detectedTechStack.joinToString()}")
                appendLine("• Design Assets: Layouts=${apk.designProfile.layoutXmlCount}, Drawables=${apk.designProfile.drawableAssetCount}, Fonts=${apk.designProfile.fontAssetCount}, Mipmaps=${apk.designProfile.mipmapIconCount}")
                appendLine("• SDK Levels: minSdk=${apk.minSdk}, targetSdk=${apk.targetSdk}")
                appendLine("• Base APK Path: ${apk.sourceApkPath} (${apk.apkSizeBytes / 1024} KB)")
                appendLine("• Signing SHA-256: ${apk.certSha256}")
                appendLine("• Signing Subject/Issuer: ${apk.certDetails.subjectDn} / ${apk.certDetails.issuerDn}")
                appendLine("• Archive Breakdown: ${apk.totalArchiveEntries} entries (${apk.dexCount} DEX, ${apk.nativeSoCount} Native .so)")
                appendLine("• Permissions (${apk.permissions.size}): ${apk.permissions.joinToString { it.shortName }}")
                appendLine("• Exported Surface: ${apk.components.count { it.isExported }} / ${apk.components.size} components exported")
            }
            repository.insert(
                EvidenceReportEntity(
                    title = "APK Audit: ${apk.appLabel} (${apk.packageName})",
                    category = "APK_AUDIT",
                    magicFormat = "APK • Score ${apk.securityScore}/100 • ${apk.designProfile.primaryUiFramework}",
                    summaryMetrics = "${apk.totalArchiveEntries} Entries • ${apk.permissions.size} Perms • ${apk.components.size} Components",
                    detailedEvidence = details,
                    engineerNotes = "Captured from APK & Design Forensics tab."
                )
            )
            withContext(Dispatchers.Main) {
                _uiState.update { it.copy(statusBannerMessage = "Saved APK Audit for '${apk.appLabel}' to Vault") }
            }
        }
    }

    fun saveCurrentWebEvidence() {
        val trace = _uiState.value.webTraceResult ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val details = buildString {
                appendLine("• Request: ${trace.requestMethod} ${trace.targetUrl}")
                appendLine("• Final Resolved URL: ${trace.finalUrl}")
                appendLine("• HTTP Status: ${trace.statusCode} ${trace.statusMessage} (${trace.protocol})")
                appendLine("• TLS Handshake: ${trace.tlsVersion} • Cipher: ${trace.cipherSuite}")
                appendLine("• Timing Breakdown: DNS ${trace.dnsDurationMs}ms | TCP ${trace.connectDurationMs}ms | TLS ${trace.tlsDurationMs}ms | Total ${trace.totalDurationMs}ms")
                if (trace.tlsCertificateChain.isNotEmpty()) {
                    appendLine("\n--- TLS Certificate Chain ---")
                    trace.tlsCertificateChain.forEach { c -> appendLine("• $c") }
                }
                appendLine("\n--- Security Header Posture ---")
                trace.securityAudit.forEach { h ->
                    appendLine("• ${h.headerName}: ${if (h.isPresent) "PRESENT (${h.valueOrWarning})" else "MISSING"}")
                }
                appendLine("\n--- Discovered Endpoints (${trace.discoveredEndpoints.size}) ---")
                trace.discoveredEndpoints.take(10).forEach { ep ->
                    appendLine("  -> $ep")
                }
            }
            repository.insert(
                EvidenceReportEntity(
                    title = "Web Trace: ${trace.requestMethod} ${trace.targetUrl.removePrefix("https://").removePrefix("http://")}",
                    category = "WEB_TRACE",
                    magicFormat = "${trace.protocol} ${trace.statusCode} • ${trace.tlsVersion}",
                    summaryMetrics = "${trace.totalDurationMs}ms RTT • ${trace.responseHeaders.size} Headers • ${trace.discoveredEndpoints.size} Endpoints",
                    detailedEvidence = details,
                    engineerNotes = "Live network & protocol trace captured via OkHttp EventListener."
                )
            )
            withContext(Dispatchers.Main) {
                _uiState.update { it.copy(statusBannerMessage = "Saved Web Trace to Evidence Vault") }
            }
        }
    }

    fun updateVaultCategoryFilter(category: String) {
        _uiState.update { it.copy(vaultCategoryFilter = category) }
    }

    fun updateVaultSearchQuery(query: String) {
        _uiState.update { it.copy(vaultSearchQuery = query) }
    }

    fun selectEvidenceReport(report: EvidenceReportEntity?) {
        _uiState.update { it.copy(selectedEvidenceReport = report) }
    }

    fun togglePinEvidence(report: EvidenceReportEntity) {
        viewModelScope.launch(Dispatchers.IO) {
            val updated = report.copy(isPinned = !report.isPinned)
            repository.update(updated)
            if (_uiState.value.selectedEvidenceReport?.id == report.id) {
                _uiState.update { it.copy(selectedEvidenceReport = updated) }
            }
        }
    }

    fun updateEvidenceNotes(report: EvidenceReportEntity, newNotes: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val updated = report.copy(engineerNotes = newNotes)
            repository.update(updated)
            _uiState.update {
                it.copy(
                    selectedEvidenceReport = if (it.selectedEvidenceReport?.id == report.id) updated else it.selectedEvidenceReport,
                    statusBannerMessage = "Engineer notes updated"
                )
            }
        }
    }

    fun deleteEvidenceReport(id: Int) {
        viewModelScope.launch(Dispatchers.IO) {
            repository.deleteById(id)
            _uiState.update {
                it.copy(
                    selectedEvidenceReport = if (it.selectedEvidenceReport?.id == id) null else it.selectedEvidenceReport,
                    statusBannerMessage = "Evidence report deleted"
                )
            }
        }
    }

    fun clearStatusBanner() {
        _uiState.update { it.copy(statusBannerMessage = null) }
    }

    class Factory(private val context: Context) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            val db = EvidenceDatabase.getInstance(context.applicationContext)
            val repo = EvidenceRepository(db.evidenceDao())
            return ReaInspectorViewModel(context.applicationContext, repo) as T
        }
    }
}
