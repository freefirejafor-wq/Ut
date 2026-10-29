package com.example.ui.screens

import android.content.Intent
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Inventory2
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.data.EvidenceReportEntity
import com.example.ui.theme.JetBrainsMonoFontFamily
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun EvidenceVaultScreen(
    reports: List<EvidenceReportEntity>,
    categoryFilter: String,
    searchQuery: String,
    selectedReport: EvidenceReportEntity?,
    onSelectCategory: (String) -> Unit,
    onSearchQueryChange: (String) -> Unit,
    onSelectReport: (EvidenceReportEntity?) -> Unit,
    onTogglePin: (EvidenceReportEntity) -> Unit,
    onUpdateNotes: (EvidenceReportEntity, String) -> Unit,
    onExportReportFile: (EvidenceReportEntity, Boolean) -> Unit,
    onExplainReportWithAi: (EvidenceReportEntity) -> Unit,
    onDeleteReport: (Int) -> Unit,
    modifier: Modifier = Modifier
) {
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current

    if (selectedReport != null) {
        BackHandler {
            onSelectReport(null)
        }
        val buildMarkdown = {
            buildString {
                appendLine("# ${selectedReport.title}")
                appendLine("- Category: ${selectedReport.category}")
                appendLine("- Format: ${selectedReport.magicFormat}")
                appendLine("- Metrics: ${selectedReport.summaryMetrics}")
                appendLine("\n## Evidence Log")
                appendLine(selectedReport.detailedEvidence)
                if (selectedReport.engineerNotes.isNotBlank()) {
                    appendLine("\n## Engineer Notes")
                    appendLine(selectedReport.engineerNotes)
                }
            }
        }
        EvidenceDetailView(
            report = selectedReport,
            onBack = { onSelectReport(null) },
            onTogglePin = { onTogglePin(selectedReport) },
            onSaveNotes = { notes -> onUpdateNotes(selectedReport, notes) },
            onCopyAll = {
                clipboard.setText(AnnotatedString(buildMarkdown()))
            },
            onShareReport = {
                val shareIntent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_SUBJECT, selectedReport.title)
                    putExtra(Intent.EXTRA_TEXT, buildMarkdown())
                }
                context.startActivity(Intent.createChooser(shareIntent, "Share Forensic Report"))
            },
            onExportJson = { onExportReportFile(selectedReport, true) },
            onExportMarkdown = { onExportReportFile(selectedReport, false) },
            onExplainWithAi = { onExplainReportWithAi(selectedReport) },
            onDelete = { onDeleteReport(selectedReport.id) },
            modifier = modifier
        )
        return
    }

    val categories = listOf(
        "ALL" to "All Evidence",
        "DEX_BINARY" to "DEX & Binary",
        "ELF_NATIVE" to "Native ELF",
        "APK_AUDIT" to "APK Audits",
        "WEB_TRACE" to "Web Traces"
    )

    val filteredReports = reports.filter { rep ->
        (categoryFilter == "ALL" || rep.category == categoryFilter) &&
            (searchQuery.isBlank() ||
                rep.title.contains(searchQuery, ignoreCase = true) ||
                rep.detailedEvidence.contains(searchQuery, ignoreCase = true) ||
                rep.engineerNotes.contains(searchQuery, ignoreCase = true))
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .testTag("evidence_vault_list"),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "FORENSIC EVIDENCE VAULT (ROOM DB)",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary
                )
                Text(
                    text = "সংরক্ষিত বাইনারি ডিসেকশন, APK অডিট, এক্সপোর্ট ও এআই বিশ্লেষণ",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = onSearchQueryChange,
                    placeholder = { Text("Search saved evidence reports, hashes, notes…") },
                    leadingIcon = { Icon(Icons.Default.Search, contentDescription = "Search Vault") },
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("vault_search_input")
                )

                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(categories, key = { it.first }) { (code, label) ->
                        FilterChip(
                            selected = categoryFilter == code,
                            onClick = { onSelectCategory(code) },
                            label = { Text(label, style = MaterialTheme.typography.labelLarge) },
                            modifier = Modifier.testTag("vault_filter_$code")
                        )
                    }
                }
            }
        }

        if (filteredReports.isEmpty()) {
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 24.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Inventory2,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(40.dp)
                        )
                        Text("No Matching Evidence Reports", style = MaterialTheme.typography.titleMedium)
                        Text(
                            text = "Save any Binary/Hex dissection, APK audit, or Web trace to persist forensic snapshots locally.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        } else {
            items(filteredReports, key = { it.id }) { report ->
                EvidenceReportItemCard(
                    report = report,
                    onClick = { onSelectReport(report) },
                    onTogglePin = { onTogglePin(report) },
                    onDelete = { onDeleteReport(report.id) }
                )
            }
        }
    }
}

@Composable
private fun EvidenceReportItemCard(
    report: EvidenceReportEntity,
    onClick: () -> Unit,
    onTogglePin: () -> Unit,
    onDelete: () -> Unit
) {
    val dateFormat = remember { SimpleDateFormat("MMM dd, HH:mm", Locale.US) }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(
                width = 1.dp,
                color = if (report.isPinned) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline,
                shape = RoundedCornerShape(14.dp)
            )
            .clickable { onClick() }
            .testTag("evidence_card_${report.id}"),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
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
                    Text(
                        text = report.category,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier
                            .clip(RoundedCornerShape(4.dp))
                            .background(MaterialTheme.colorScheme.primaryContainer)
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                    Text(
                        text = dateFormat.format(Date(report.timestamp)),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Row {
                    IconButton(onClick = onTogglePin, modifier = Modifier.size(32.dp)) {
                        Icon(
                            imageVector = Icons.Default.PushPin,
                            contentDescription = "Pin report",
                            tint = if (report.isPinned) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                    IconButton(onClick = onDelete, modifier = Modifier.size(32.dp)) {
                        Icon(
                            imageVector = Icons.Default.DeleteOutline,
                            contentDescription = "Delete report",
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
            }

            Text(
                text = report.title,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )

            Text(
                text = report.magicFormat,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.secondary
            )

            Text(
                text = report.summaryMetrics,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            if (report.engineerNotes.isNotBlank()) {
                Surface(
                    color = MaterialTheme.colorScheme.background,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = "Note: ${report.engineerNotes}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.tertiary,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.padding(8.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun EvidenceDetailView(
    report: EvidenceReportEntity,
    onBack: () -> Unit,
    onTogglePin: () -> Unit,
    onSaveNotes: (String) -> Unit,
    onCopyAll: () -> Unit,
    onShareReport: () -> Unit,
    onExportJson: () -> Unit,
    onExportMarkdown: () -> Unit,
    onExplainWithAi: () -> Unit,
    onDelete: () -> Unit,
    modifier: Modifier = Modifier
) {
    var notesInput by remember(report.id, report.engineerNotes) {
        mutableStateOf(report.engineerNotes)
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .testTag("evidence_detail_view"),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedButton(
                    onClick = onBack,
                    modifier = Modifier.testTag("evidence_back_button")
                ) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Back")
                }

                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    IconButton(onClick = onShareReport) {
                        Icon(
                            imageVector = Icons.Default.Share,
                            contentDescription = "Share Report",
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                    IconButton(onClick = onTogglePin) {
                        Icon(
                            imageVector = Icons.Default.PushPin,
                            contentDescription = "Pin",
                            tint = if (report.isPinned) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    IconButton(onClick = onCopyAll) {
                        Icon(
                            imageVector = Icons.Default.ContentCopy,
                            contentDescription = "Copy Markdown Report"
                        )
                    }
                    IconButton(onClick = onDelete) {
                        Icon(
                            imageVector = Icons.Default.DeleteOutline,
                            contentDescription = "Delete Report",
                            tint = MaterialTheme.colorScheme.error
                        )
                    }
                }
            }
        }

        item {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(14.dp)),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(report.category, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                    Text(report.title, style = MaterialTheme.typography.headlineMedium)
                    Text(report.magicFormat, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary)
                    Text(report.summaryMetrics, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.tertiary)

                    Spacer(modifier = Modifier.height(4.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = onExplainWithAi,
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.AutoAwesome, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("AI দিয়ে বুঝুন")
                        }
                        OutlinedButton(onClick = onExportJson) {
                            Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("JSON")
                        }
                        OutlinedButton(onClick = onExportMarkdown) {
                            Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(".MD")
                        }
                    }
                }
            }
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "ENGINEER INVESTIGATION NOTES",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                    OutlinedTextField(
                        value = notesInput,
                        onValueChange = { notesInput = it },
                        placeholder = { Text("Add reverse-engineering observations, offsets, or hypothesis…") },
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("engineer_notes_input")
                    )
                    Button(
                        onClick = { onSaveNotes(notesInput) },
                        modifier = Modifier
                            .align(Alignment.End)
                            .testTag("save_notes_button")
                    ) {
                        Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Save Notes")
                    }
                }
            }
        }

        item {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(14.dp)),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "CAPTURED HARD EVIDENCE LOG",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.secondary
                    )
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = report.detailedEvidence,
                        fontFamily = JetBrainsMonoFontFamily,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }
    }
}
