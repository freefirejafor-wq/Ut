package com.example.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
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
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.analyzer.BinaryAnalysisResult
import com.example.analyzer.BinaryTargetPreset
import com.example.analyzer.DecodedBinaryStructureItem
import com.example.analyzer.ExtractedStringItem
import com.example.analyzer.HeaderField
import com.example.analyzer.HexDumpRow
import com.example.analyzer.StringCategory
import com.example.analyzer.YaraSignatureMatch
import com.example.ui.theme.JetBrainsMonoFontFamily

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun BinaryInspectorScreen(
    presets: List<BinaryTargetPreset>,
    selectedPresetId: String,
    isLoading: Boolean,
    result: BinaryAnalysisResult?,
    subTab: Int,
    minStringLength: Int,
    selectedStringCategory: StringCategory,
    stringSearchQuery: String,
    hexSearchQuery: String,
    hexStartOffset: Int,
    hexRows: List<HexDumpRow>,
    onSelectPreset: (String) -> Unit,
    onPickExternalFile: () -> Unit,
    onSaveEvidence: () -> Unit,
    onExplainWithAi: (String, String) -> Unit,
    onSelectSubTab: (Int) -> Unit,
    onChangeMinStringLength: (Int) -> Unit,
    onSelectStringCategory: (StringCategory) -> Unit,
    onStringSearchChange: (String) -> Unit,
    onHexSearchAndOffsetChange: (String, Int) -> Unit,
    modifier: Modifier = Modifier
) {
    val clipboard = LocalClipboardManager.current

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .testTag("binary_inspector_list"),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Target Preset Strip & File Picker Action
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "ON-DEVICE BINARY TARGETS",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = "রিয়েল ডেক্স (DEX), ম্যানিফেস্ট, নেটিভ ELF ও YARA বিশ্লেষণ",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        OutlinedButton(
                            onClick = onPickExternalFile,
                            modifier = Modifier.testTag("open_external_file_button"),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.FolderOpen,
                                contentDescription = "Open File",
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Open", style = MaterialTheme.typography.labelLarge)
                        }
                        Button(
                            onClick = onSaveEvidence,
                            modifier = Modifier.testTag("save_binary_evidence_button"),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.primary,
                                contentColor = MaterialTheme.colorScheme.onPrimary
                            )
                        ) {
                            Icon(
                                imageVector = Icons.Default.BookmarkAdd,
                                contentDescription = "Save Evidence",
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Save", style = MaterialTheme.typography.labelLarge)
                        }
                    }
                }

                LazyRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.testTag("binary_presets_row")
                ) {
                    items(presets, key = { it.id }) { preset ->
                        val isSelected = preset.id == selectedPresetId
                        FilterChip(
                            selected = isSelected,
                            onClick = { onSelectPreset(preset.id) },
                            label = {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    Text(
                                        text = preset.badge,
                                        style = MaterialTheme.typography.labelSmall,
                                        color = if (isSelected) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.primary,
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(4.dp))
                                            .background(
                                                if (isSelected) MaterialTheme.colorScheme.primary
                                                else MaterialTheme.colorScheme.primaryContainer
                                            )
                                            .padding(horizontal = 5.dp, vertical = 2.dp)
                                    )
                                    Text(preset.title, style = MaterialTheme.typography.labelLarge)
                                }
                            },
                            colors = FilterChipDefaults.filterChipColors(
                                selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                                selectedLabelColor = MaterialTheme.colorScheme.onSurface
                            ),
                            modifier = Modifier.testTag("preset_chip_${preset.id}")
                        )
                    }
                }
            }
        }

        if (isLoading) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(32.dp),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator()
                }
            }
        } else if (result != null) {
            // Binary Summary Hero Card
            item {
                BinaryOverviewHeroCard(
                    result = result,
                    onCopyHash = { clipboard.setText(AnnotatedString(it)) },
                    onExplainWithAi = {
                        onExplainWithAi(
                            "Binary: ${result.sourceName} (${result.formatBadge})",
                            "এই '${result.sourceName}' (${result.formatName}) বাইনারি ফাইলটির কাজ কী? এর Magic Bytes (${result.magicHex}), Entropy (${"%.2f".format(result.overallEntropy)}), YARA সিগনেচার এবং ভেতরের স্ট্রাকচার সহজ বাংলায় বুঝিয়ে বলো।"
                        )
                    }
                )
            }

            // Sub-Tab Selector
            item {
                val tabs = listOf(
                    "Headers (${result.headerFields.size})",
                    "Hex Dump",
                    "Strings (${result.extractedStrings.size})",
                    "YARA & Decoded (${result.signatureMatches.size + result.decodedStructures.size})",
                    "Entropy"
                )
                ScrollableTabRow(
                    selectedTabIndex = subTab,
                    edgePadding = 0.dp,
                    containerColor = MaterialTheme.colorScheme.surface,
                    contentColor = MaterialTheme.colorScheme.primary,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .testTag("binary_sub_tabs")
                ) {
                    tabs.forEachIndexed { index, title ->
                        Tab(
                            selected = subTab == index,
                            onClick = { onSelectSubTab(index) },
                            text = {
                                Text(
                                    text = title,
                                    style = MaterialTheme.typography.labelLarge,
                                    fontWeight = if (subTab == index) FontWeight.Bold else FontWeight.Normal
                                )
                            },
                            modifier = Modifier.testTag("binary_subtab_$index")
                        )
                    }
                }
            }

            when (subTab) {
                0 -> {
                    // Header Structure Breakdown
                    items(result.headerFields, key = { it.name + it.offsetRange }) { field ->
                        HeaderFieldRowCard(
                            field = field,
                            onCopy = {
                                clipboard.setText(AnnotatedString("${field.name} [${field.offsetRange}]: ${field.decodedValue} (${field.rawHex})"))
                            },
                            onAskAi = {
                                onExplainWithAi(
                                    "Header: ${field.name}",
                                    "বাইনারি হেডার ফিল্ড '${field.name}' (Offset ${field.offsetRange}, Value: ${field.decodedValue}, Raw Hex: ${field.rawHex})-এর কাজ কী এবং এটি কেন গুরুত্বপূর্ণ তা বাংলায় বুঝিয়ে বলো।"
                                )
                            }
                        )
                    }
                }

                1 -> {
                    // Interactive Hex + ASCII Dump
                    item {
                        HexDumpControlsCard(
                            hexSearchQuery = hexSearchQuery,
                            hexStartOffset = hexStartOffset,
                            maxBytes = result.rawSampleBytes.size,
                            onSearchChange = { onHexSearchAndOffsetChange(it, hexStartOffset) },
                            onOffsetChange = { onHexSearchAndOffsetChange(hexSearchQuery, it) }
                        )
                    }
                    item {
                        Card(
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                            modifier = Modifier
                                .fillMaxWidth()
                                .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(12.dp))
                        ) {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .horizontalScroll(rememberScrollState())
                                    .padding(12.dp),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Text(
                                    text = "OFFSET   | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ASCII",
                                    fontFamily = JetBrainsMonoFontFamily,
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.secondary
                                )
                                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                                if (hexRows.isEmpty()) {
                                    Text(
                                        text = "No matching hex or ASCII sequence in current buffer.",
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        modifier = Modifier.padding(vertical = 12.dp)
                                    )
                                } else {
                                    hexRows.forEach { row ->
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Text(
                                                text = row.offsetHex,
                                                fontFamily = JetBrainsMonoFontFamily,
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.primary
                                            )
                                            Text(
                                                text = " | ${row.hexBytes} | ",
                                                fontFamily = JetBrainsMonoFontFamily,
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurface
                                            )
                                            Text(
                                                text = row.asciiText,
                                                fontFamily = JetBrainsMonoFontFamily,
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.tertiary
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                2 -> {
                    // Extracted Strings & Symbols
                    item {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedTextField(
                                value = stringSearchQuery,
                                onValueChange = onStringSearchChange,
                                placeholder = { Text("Search extracted strings, classes, JNI symbols, URLs…") },
                                leadingIcon = { Icon(Icons.Default.Search, contentDescription = "Search strings") },
                                singleLine = true,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .testTag("string_search_input")
                            )

                            FlowRow(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                StringCategory.entries.forEach { cat ->
                                    FilterChip(
                                        selected = selectedStringCategory == cat,
                                        onClick = { onSelectStringCategory(cat) },
                                        label = { Text(cat.label, style = MaterialTheme.typography.labelMedium) },
                                        modifier = Modifier.testTag("string_cat_${cat.name}")
                                    )
                                }
                            }

                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Text(
                                    text = "Min Length:",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                listOf(4, 5, 8, 12).forEach { len ->
                                    AssistChip(
                                        onClick = { onChangeMinStringLength(len) },
                                        label = {
                                            Text(
                                                text = "${len}+ chars",
                                                color = if (minStringLength == len) MaterialTheme.colorScheme.primary
                                                else MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                    )
                                }
                            }
                        }
                    }

                    val filteredStrings = result.extractedStrings.filter { item ->
                        (selectedStringCategory == StringCategory.ALL || item.category == selectedStringCategory) &&
                            (stringSearchQuery.isBlank() ||
                                item.value.contains(stringSearchQuery, ignoreCase = true) ||
                                item.offsetHex.contains(stringSearchQuery, ignoreCase = true))
                    }

                    if (filteredStrings.isEmpty()) {
                        item {
                            Text(
                                text = "No strings match the current filter criteria.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(16.dp)
                            )
                        }
                    } else {
                        items(filteredStrings.take(150), key = { "${it.offset}_${it.value.take(20)}" }) { strItem ->
                            ExtractedStringRow(
                                item = strItem,
                                onCopy = { clipboard.setText(AnnotatedString(strItem.value)) }
                            )
                        }
                    }
                }

                3 -> {
                    // YARA Signatures & Decoded Binary Structures (DEX Classes / ELF Symbols / AXML Tags)
                    item {
                        Text(
                            text = "YARA-STYLE SECURITY & FORMAT SIGNATURES (${result.signatureMatches.size})",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                    items(result.signatureMatches, key = { "${it.ruleId}_${it.offsetHex}" }) { sig ->
                        YaraSignatureCard(
                            sig = sig,
                            onAskAi = {
                                onExplainWithAi(
                                    "YARA Rule: ${sig.ruleId}",
                                    "বাইনারিতে পাওয়া '${sig.title}' (${sig.ruleId}, Preview: ${sig.matchedPreview})-এর কাজ কী এবং এতে কোনো সিকিউরিটি ঝুঁকি আছে কি না বাংলায় বুঝিয়ে বলো।"
                                )
                            }
                        )
                    }

                    if (result.decodedStructures.isNotEmpty()) {
                        item {
                            Text(
                                text = "DECODED STRUCTURE TABLE (DEX CLASSES / ELF SYMBOLS / AXML NODES)",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.secondary,
                                modifier = Modifier.padding(top = 8.dp)
                            )
                        }
                        items(result.decodedStructures, key = { "${it.offsetHex}_${it.name.take(24)}" }) { st ->
                            DecodedStructureRowCard(
                                item = st,
                                onCopy = { clipboard.setText(AnnotatedString(st.name)) }
                            )
                        }
                    }
                }

                4 -> {
                    // Shannon Entropy Spectrum & Byte Distribution Canvas
                    item {
                        EntropySpectrumCard(result = result)
                    }
                }
            }
        }
    }
}

@Composable
private fun BinaryOverviewHeroCard(
    result: BinaryAnalysisResult,
    onCopyHash: (String) -> Unit,
    onExplainWithAi: () -> Unit
) {
    val gradient = Brush.linearGradient(
        colors = listOf(
            MaterialTheme.colorScheme.surfaceVariant,
            MaterialTheme.colorScheme.surface
        )
    )
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(16.dp)),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(
            modifier = Modifier
                .background(gradient)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Surface(
                        color = MaterialTheme.colorScheme.primaryContainer,
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Memory,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(16.dp)
                            )
                            Text(
                                text = result.formatBadge,
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                    }
                    Column {
                        Text(
                            text = result.sourceName,
                            style = MaterialTheme.typography.titleMedium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = result.formatName,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.secondary
                        )
                    }
                }

                AssistChip(
                    onClick = onExplainWithAi,
                    label = { Text("AI দিয়ে বুঝুন", style = MaterialTheme.typography.labelMedium) },
                    leadingIcon = {
                        Icon(
                            imageVector = Icons.Default.AutoAwesome,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(16.dp)
                        )
                    },
                    modifier = Modifier.testTag("binary_explain_ai_button")
                )
            }

            Text(
                text = "Architecture: ${result.architectureInfo} • Size: ${result.totalSizeBytes / 1024} KB",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                MetricPill(
                    label = "MAGIC BYTES",
                    value = result.magicHex,
                    modifier = Modifier.weight(1f)
                )
                MetricPill(
                    label = "SHANNON ENTROPY",
                    value = "${"%.2f".format(result.overallEntropy)} / 8.00 b/B",
                    modifier = Modifier.weight(1f)
                )
            }

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colorScheme.background)
                    .clickable { onCopyHash(result.sha256Hash) }
                    .padding(horizontal = 10.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "SHA-256 FINGERPRINT (TAP TO COPY)",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = result.sha256Hash,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                Icon(
                    imageVector = Icons.Default.ContentCopy,
                    contentDescription = "Copy SHA-256",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(16.dp)
                )
            }
        }
    }
}

@Composable
private fun YaraSignatureCard(
    sig: YaraSignatureMatch,
    onAskAi: () -> Unit
) {
    val badgeColor = when (sig.severity) {
        "HIGH" -> MaterialTheme.colorScheme.error
        "MEDIUM" -> MaterialTheme.colorScheme.tertiary
        else -> MaterialTheme.colorScheme.primary
    }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(0.5.dp, badgeColor, RoundedCornerShape(10.dp)),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(
                        imageVector = Icons.Default.Shield,
                        contentDescription = null,
                        tint = badgeColor,
                        modifier = Modifier.size(16.dp)
                    )
                    Text(
                        text = sig.severity,
                        style = MaterialTheme.typography.labelSmall,
                        color = badgeColor
                    )
                    Text(
                        text = sig.title,
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
                IconButton(onClick = onAskAi, modifier = Modifier.size(28.dp)) {
                    Icon(
                        imageVector = Icons.Default.AutoAwesome,
                        contentDescription = "Ask AI about signature",
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }
            Text(
                text = "${sig.offsetHex} • ${sig.matchedPreview}",
                fontFamily = JetBrainsMonoFontFamily,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.secondary
            )
            Text(
                text = sig.explanationBn,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun DecodedStructureRowCard(
    item: DecodedBinaryStructureItem,
    onCopy: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCopy() },
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = item.typeBadge,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier
                            .clip(RoundedCornerShape(4.dp))
                            .background(MaterialTheme.colorScheme.primaryContainer)
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                    Text(
                        text = item.offsetHex,
                        fontFamily = JetBrainsMonoFontFamily,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.secondary
                    )
                }
                Text(
                    text = item.name,
                    fontFamily = JetBrainsMonoFontFamily,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = item.detail,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Icon(
                imageVector = Icons.Default.ContentCopy,
                contentDescription = "Copy",
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(16.dp)
            )
        }
    }
}

@Composable
private fun MetricPill(
    label: String,
    value: String,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.background)
            .padding(horizontal = 10.dp, vertical = 8.dp)
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun HeaderFieldRowCard(
    field: HeaderField,
    onCopy: () -> Unit,
    onAskAi: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCopy() },
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(10.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = field.offsetRange,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.secondary,
                        modifier = Modifier
                            .clip(RoundedCornerShape(4.dp))
                            .background(MaterialTheme.colorScheme.secondaryContainer)
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                    Text(
                        text = field.name,
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
                Text(
                    text = field.decodedValue,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.primary
                )
                Text(
                    text = "Raw: ${field.rawHex}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Row {
                IconButton(onClick = onAskAi) {
                    Icon(
                        imageVector = Icons.Default.AutoAwesome,
                        contentDescription = "Ask AI about header",
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                }
                IconButton(onClick = onCopy) {
                    Icon(
                        imageVector = Icons.Default.ContentCopy,
                        contentDescription = "Copy header field",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun HexDumpControlsCard(
    hexSearchQuery: String,
    hexStartOffset: Int,
    maxBytes: Int,
    onSearchChange: (String) -> Unit,
    onOffsetChange: (Int) -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            value = hexSearchQuery,
            onValueChange = onSearchChange,
            placeholder = { Text("Search hex bytes (e.g. 64 65 78) or ASCII…") },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = "Search Hex") },
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .testTag("hex_search_input")
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Offset: 0x%06X / 0x%06X".format(hexStartOffset, maxBytes),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary
            )
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                AssistChip(onClick = { onOffsetChange(0) }, label = { Text("0x0000") })
                AssistChip(onClick = { onOffsetChange(hexStartOffset - 256) }, label = { Text("-256B") })
                AssistChip(onClick = { onOffsetChange(hexStartOffset + 256) }, label = { Text("+256B") })
                AssistChip(onClick = { onOffsetChange(hexStartOffset + 1024) }, label = { Text("+1KB") })
            }
        }
    }
}

@Composable
private fun ExtractedStringRow(
    item: ExtractedStringItem,
    onCopy: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCopy() },
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(10.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = item.offsetHex,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        text = item.category.label,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.secondary,
                        modifier = Modifier
                            .clip(RoundedCornerShape(4.dp))
                            .background(MaterialTheme.colorScheme.secondaryContainer)
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
                Text(
                    text = item.value,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
            Icon(
                imageVector = Icons.Default.ContentCopy,
                contentDescription = "Copy string",
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(16.dp)
            )
        }
    }
}

@Composable
private fun EntropySpectrumCard(result: BinaryAnalysisResult) {
    val primaryColor = MaterialTheme.colorScheme.primary
    val secondaryColor = MaterialTheme.colorScheme.secondary
    val tertiaryColor = MaterialTheme.colorScheme.tertiary
    val errorColor = MaterialTheme.colorScheme.error
    val gridColor = MaterialTheme.colorScheme.outlineVariant

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(14.dp)),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = "32-Block Sliding Window Shannon Entropy",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = result.entropyAssessment,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.primary
            )

            Canvas(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(150.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colorScheme.background)
                    .padding(10.dp)
            ) {
                val w = size.width
                val h = size.height
                val blocks = result.blockEntropies
                if (blocks.isNotEmpty()) {
                    val y4 = h * (1f - 4f / 8f)
                    val y7 = h * (1f - 7f / 8f)
                    drawLine(gridColor, Offset(0f, y4), Offset(w, y4), strokeWidth = 1.5f)
                    drawLine(gridColor, Offset(0f, y7), Offset(w, y7), strokeWidth = 1.5f)

                    val barWidth = (w / blocks.size) * 0.72f
                    val step = w / blocks.size
                    blocks.forEachIndexed { i, ent ->
                        val ratio = (ent / 8f).coerceIn(0.04f, 1f)
                        val barH = h * ratio
                        val barColor = when {
                            ent >= 7.1f -> errorColor
                            ent >= 5.5f -> tertiaryColor
                            ent >= 3.5f -> primaryColor
                            else -> secondaryColor
                        }
                        drawRoundRect(
                            color = barColor,
                            topLeft = Offset(i * step + (step - barWidth) / 2f, h - barH),
                            size = Size(barWidth, barH),
                            cornerRadius = CornerRadius(4f, 4f)
                        )
                    }
                }
            }

            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

            Text(
                text = "Byte Class Distribution",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurface
            )

            ByteDistributionRow("Printable ASCII (0x20..0x7E)", result.printableAsciiPercent, primaryColor)
            ByteDistributionRow("Null Padding Bytes (0x00)", result.nullBytesPercent, secondaryColor)
            ByteDistributionRow("High / Non-ASCII Bytes (0x80..0xFF)", result.highBytesPercent, tertiaryColor)
        }
    }
}

@Composable
private fun ByteDistributionRow(
    label: String,
    percent: Float,
    color: androidx.compose.ui.graphics.Color
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("${"%.1f".format(percent)}%", style = MaterialTheme.typography.labelMedium, color = color)
        }
        LinearProgressIndicator(
            progress = { (percent / 100f).coerceIn(0f, 1f) },
            color = color,
            trackColor = MaterialTheme.colorScheme.background,
            modifier = Modifier
                .fillMaxWidth()
                .height(6.dp)
                .clip(RoundedCornerShape(3.dp))
        )
    }
}
