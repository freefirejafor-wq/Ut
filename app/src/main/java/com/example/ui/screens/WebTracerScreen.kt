package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.analyzer.WebBehaviorTracer
import com.example.analyzer.WebTraceResult
import com.example.ui.theme.JetBrainsMonoFontFamily

@Composable
fun WebTracerScreen(
    targetUrlInput: String,
    requestMethod: String,
    customHeaders: String,
    requestBody: String,
    showAdvancedBuilder: Boolean,
    isTracing: Boolean,
    traceResult: WebTraceResult?,
    subTab: Int,
    onUrlChange: (String) -> Unit,
    onMethodChange: (String) -> Unit,
    onCustomHeadersChange: (String) -> Unit,
    onRequestBodyChange: (String) -> Unit,
    onToggleAdvancedBuilder: () -> Unit,
    onRunTrace: (String) -> Unit,
    onExplainWithAi: (String, String) -> Unit,
    onSelectSubTab: (Int) -> Unit,
    onSaveWebEvidence: () -> Unit,
    modifier: Modifier = Modifier
) {
    val clipboard = LocalClipboardManager.current

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .testTag("web_tracer_list"),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "LIVE HTTP, TLS & DOM BEHAVIOR TRACER",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = "কাস্টম রিকোয়েস্ট, TLS সার্টিফিকেট চেইন ও কোড জেনারেটর",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        OutlinedButton(
                            onClick = onToggleAdvancedBuilder,
                            modifier = Modifier.testTag("toggle_web_builder_button"),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                        ) {
                            Icon(Icons.Default.Tune, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(if (showAdvancedBuilder) "Hide Builder" else "Method/Headers", style = MaterialTheme.typography.labelLarge)
                        }
                        if (traceResult != null) {
                            OutlinedButton(
                                onClick = onSaveWebEvidence,
                                modifier = Modifier.testTag("save_web_evidence_button"),
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                            ) {
                                Icon(Icons.Default.BookmarkAdd, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Save", style = MaterialTheme.typography.labelLarge)
                            }
                        }
                    }
                }

                // HTTP Method Selector Chips
                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(WebBehaviorTracer.supportedMethods) { m ->
                        FilterChip(
                            selected = requestMethod == m,
                            onClick = { onMethodChange(m) },
                            label = { Text(m, style = MaterialTheme.typography.labelLarge) }
                        )
                    }
                }

                AnimatedVisibility(visible = showAdvancedBuilder) {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            OutlinedTextField(
                                value = customHeaders,
                                onValueChange = onCustomHeadersChange,
                                label = { Text("Custom Headers (Key: Value per line)") },
                                placeholder = { Text("Authorization: Bearer token123\nX-Custom-Client: REA") },
                                modifier = Modifier.fillMaxWidth()
                            )
                            if (requestMethod == "POST" || requestMethod == "PUT" || requestMethod == "DELETE") {
                                OutlinedTextField(
                                    value = requestBody,
                                    onValueChange = onRequestBodyChange,
                                    label = { Text("JSON / Raw Request Body") },
                                    placeholder = { Text("{\"query\": \"status\"}") },
                                    modifier = Modifier.fillMaxWidth()
                                )
                            }
                        }
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = targetUrlInput,
                        onValueChange = onUrlChange,
                        placeholder = { Text("https://api.github.com/repos/morluto/rea") },
                        leadingIcon = { Icon(Icons.Default.Language, contentDescription = null) },
                        singleLine = true,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("web_url_input")
                    )
                    Button(
                        onClick = { onRunTrace(targetUrlInput) },
                        enabled = !isTracing,
                        modifier = Modifier
                            .height(54.dp)
                            .testTag("run_web_trace_button")
                    ) {
                        Icon(Icons.Default.PlayArrow, contentDescription = "Trace")
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(requestMethod)
                    }
                }

                LazyRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.testTag("web_presets_row")
                ) {
                    items(WebBehaviorTracer.presetEndpoints, key = { it.first }) { (url, label) ->
                        AssistChip(
                            onClick = { onRunTrace(url) },
                            label = { Text(label, style = MaterialTheme.typography.labelMedium) }
                        )
                    }
                }
            }
        }

        if (isTracing) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(20.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(28.dp))
                        Column {
                            Text("Executing $requestMethod + DNS + TCP + TLS Handshake…", style = MaterialTheme.typography.titleSmall)
                            Text(targetUrlInput, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary)
                        }
                    }
                }
            }
        } else if (traceResult != null) {
            item {
                WebTelemetrySummaryCard(
                    trace = traceResult,
                    onExplainWithAi = {
                        onExplainWithAi(
                            "Web Trace: ${traceResult.requestMethod} ${traceResult.finalUrl}",
                            "এই ওয়েব ট্রেসটি (${traceResult.requestMethod} ${traceResult.finalUrl}, Status ${traceResult.statusCode}, Protocol ${traceResult.protocol}, TLS ${traceResult.tlsVersion}) এবং এর সিকিউরিটি হেডারগুলোর কাজ ও ঝুঁকি সহজ বাংলায় বুঝিয়ে বলো।"
                        )
                    }
                )
            }

            item {
                val tabs = listOf(
                    "Security & Headers (${traceResult.responseHeaders.size})",
                    "TLS Certs & Routes (${traceResult.discoveredEndpoints.size})",
                    "Payload Preview",
                    "Replay (4 Languages)"
                )
                ScrollableTabRow(
                    selectedTabIndex = subTab,
                    edgePadding = 0.dp,
                    containerColor = MaterialTheme.colorScheme.surface,
                    contentColor = MaterialTheme.colorScheme.primary,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .testTag("web_sub_tabs")
                ) {
                    tabs.forEachIndexed { idx, title ->
                        Tab(
                            selected = subTab == idx,
                            onClick = { onSelectSubTab(idx) },
                            text = {
                                Text(
                                    text = title,
                                    style = MaterialTheme.typography.labelLarge,
                                    fontWeight = if (subTab == idx) FontWeight.Bold else FontWeight.Normal
                                )
                            }
                        )
                    }
                }
            }

            when (subTab) {
                0 -> {
                    item {
                        Text(
                            text = "SECURITY HEADER POSTURE AUDIT",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.secondary
                        )
                    }
                    items(traceResult.securityAudit, key = { it.headerName }) { audit ->
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Icon(
                                    imageVector = if (audit.isPresent) Icons.Default.CheckCircle else Icons.Default.Warning,
                                    contentDescription = null,
                                    tint = if (audit.isPresent) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.tertiary,
                                    modifier = Modifier.size(20.dp)
                                )
                                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                    Text(audit.headerName, style = MaterialTheme.typography.titleMedium)
                                    Text(
                                        text = audit.valueOrWarning,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = if (audit.isPresent) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.tertiary,
                                        maxLines = 2,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Text(audit.purpose, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                            }
                        }
                    }

                    if (traceResult.responseHeaders.isNotEmpty()) {
                        item {
                            Text(
                                text = "RAW HTTP RESPONSE HEADERS",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.secondary,
                                modifier = Modifier.padding(top = 8.dp)
                            )
                        }
                        items(traceResult.responseHeaders.take(40)) { (name, value) ->
                            Card(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { clipboard.setText(AnnotatedString("$name: $value")) },
                                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                            ) {
                                Column(modifier = Modifier.padding(10.dp)) {
                                    Text(name, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                                    Text(value, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface)
                                }
                            }
                        }
                    }
                }

                1 -> {
                    if (traceResult.tlsCertificateChain.isNotEmpty()) {
                        item {
                            Text(
                                text = "TLS PEER X.509 CERTIFICATE CHAIN (${traceResult.tlsCertificateChain.size})",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                        items(traceResult.tlsCertificateChain) { certDesc ->
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                            ) {
                                Text(
                                    text = certDesc,
                                    fontFamily = JetBrainsMonoFontFamily,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurface,
                                    modifier = Modifier.padding(10.dp)
                                )
                            }
                        }
                    }

                    if (traceResult.discoveredEndpoints.isNotEmpty()) {
                        item {
                            Text(
                                text = "DISCOVERED URLS & API ROUTES (TAP TO TRACE)",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.padding(top = 6.dp)
                            )
                        }
                        items(traceResult.discoveredEndpoints) { ep ->
                            Card(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        if (ep.startsWith("http")) onRunTrace(ep)
                                        else clipboard.setText(AnnotatedString(ep))
                                    },
                                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = ep,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.secondary,
                                        modifier = Modifier.weight(1f)
                                    )
                                    Icon(
                                        imageVector = if (ep.startsWith("http")) Icons.Default.PlayArrow else Icons.Default.ContentCopy,
                                        contentDescription = "Inspect",
                                        tint = MaterialTheme.colorScheme.primary,
                                        modifier = Modifier.size(18.dp)
                                    )
                                }
                            }
                        }
                    }

                    if (traceResult.discoveredScriptsAndKeys.isNotEmpty()) {
                        item {
                            Text(
                                text = "DISCOVERED SCRIPTS & JSON SCHEMA KEYS",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.tertiary,
                                modifier = Modifier.padding(top = 8.dp)
                            )
                        }
                        items(traceResult.discoveredScriptsAndKeys) { itemStr ->
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                            ) {
                                Text(
                                    text = itemStr,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurface,
                                    modifier = Modifier.padding(10.dp)
                                )
                            }
                        }
                    }
                }

                2 -> {
                    item {
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(12.dp)),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                        ) {
                            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = "CAPTURED PAYLOAD (${traceResult.contentType})",
                                        style = MaterialTheme.typography.labelMedium,
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                    IconButton(onClick = { clipboard.setText(AnnotatedString(traceResult.payloadPreview)) }) {
                                        Icon(Icons.Default.ContentCopy, contentDescription = "Copy payload", modifier = Modifier.size(18.dp))
                                    }
                                }
                                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                                Text(
                                    text = traceResult.payloadPreview.ifBlank { traceResult.errorMessage ?: "Empty response payload" },
                                    fontFamily = JetBrainsMonoFontFamily,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                            }
                        }
                    }
                }

                3 -> {
                    item {
                        CodeSnippetCard(
                            title = "1. Reconstructed cURL Command",
                            code = traceResult.curlSnippet,
                            onCopy = { clipboard.setText(AnnotatedString(traceResult.curlSnippet)) }
                        )
                    }
                    item {
                        CodeSnippetCard(
                            title = "2. Kotlin OkHttp Client",
                            code = traceResult.kotlinOkHttpSnippet,
                            onCopy = { clipboard.setText(AnnotatedString(traceResult.kotlinOkHttpSnippet)) }
                        )
                    }
                    item {
                        CodeSnippetCard(
                            title = "3. Python (requests)",
                            code = traceResult.pythonRequestsSnippet,
                            onCopy = { clipboard.setText(AnnotatedString(traceResult.pythonRequestsSnippet)) }
                        )
                    }
                    item {
                        CodeSnippetCard(
                            title = "4. JavaScript / Node.js (fetch)",
                            code = traceResult.jsFetchSnippet,
                            onCopy = { clipboard.setText(AnnotatedString(traceResult.jsFetchSnippet)) }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun WebTelemetrySummaryCard(
    trace: WebTraceResult,
    onExplainWithAi: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(16.dp)),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "${trace.requestMethod} • ${trace.finalUrl}",
                        style = MaterialTheme.typography.titleMedium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = "${trace.protocol} • ${trace.tlsVersion} • ${trace.cipherSuite}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.secondary
                    )
                }
                val isOk = trace.statusCode in 200..299
                Surface(
                    color = if (isOk) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.errorContainer,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(
                        text = if (trace.statusCode > 0) "${trace.statusCode} ${trace.statusMessage}" else "ERR",
                        style = MaterialTheme.typography.titleSmall,
                        color = if (isOk) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                    )
                }
            }

            if (trace.errorMessage != null) {
                Text(
                    text = trace.errorMessage,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                TimingBox("DNS", "${trace.dnsDurationMs} ms", Modifier.weight(1f))
                TimingBox("TCP", "${trace.connectDurationMs} ms", Modifier.weight(1f))
                TimingBox("TLS", "${trace.tlsDurationMs} ms", Modifier.weight(1f))
                TimingBox("TOTAL RTT", "${trace.totalDurationMs} ms", Modifier.weight(1f))
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                val total = trace.totalDurationMs.coerceAtLeast(1L).toFloat()
                LinearProgressIndicator(
                    progress = { ((trace.dnsDurationMs + trace.connectDurationMs + trace.tlsDurationMs) / total).coerceIn(0.15f, 1f) },
                    color = MaterialTheme.colorScheme.primary,
                    trackColor = MaterialTheme.colorScheme.secondaryContainer,
                    modifier = Modifier
                        .weight(1f)
                        .height(6.dp)
                        .clip(RoundedCornerShape(3.dp))
                )
                Spacer(modifier = Modifier.width(12.dp))
                AssistChip(
                    onClick = onExplainWithAi,
                    label = { Text("AI দিয়ে বুঝুন", style = MaterialTheme.typography.labelMedium) },
                    leadingIcon = {
                        Icon(Icons.Default.AutoAwesome, contentDescription = null, modifier = Modifier.size(16.dp))
                    },
                    modifier = Modifier.testTag("web_explain_ai_button")
                )
            }
        }
    }
}

@Composable
private fun TimingBox(
    label: String,
    value: String,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.background)
            .padding(horizontal = 8.dp, vertical = 6.dp)
    ) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
    }
}

@Composable
private fun CodeSnippetCard(
    title: String,
    code: String,
    onCopy: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(12.dp)),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(title, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.secondary)
                IconButton(onClick = onCopy) {
                    Icon(Icons.Default.ContentCopy, contentDescription = "Copy code", modifier = Modifier.size(18.dp))
                }
            }
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Text(
                text = code,
                fontFamily = JetBrainsMonoFontFamily,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.horizontalScroll(rememberScrollState())
            )
        }
    }
}
