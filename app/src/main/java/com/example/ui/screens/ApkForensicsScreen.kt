package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Palette
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.VerifiedUser
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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import com.example.analyzer.ApkAuditReport
import com.example.analyzer.ApkEntrySummary
import com.example.analyzer.InstalledPackageBrief
import com.example.ui.theme.JetBrainsMonoFontFamily

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ApkForensicsScreen(
    packages: List<InstalledPackageBrief>,
    selectedPackageName: String,
    report: ApkAuditReport?,
    isLoading: Boolean,
    subTab: Int,
    onSelectPackage: (String) -> Unit,
    onPickExternalApk: () -> Unit,
    onBackupCopyApk: (ApkAuditReport) -> Unit,
    onExplainWithAi: (String, String) -> Unit,
    onSelectSubTab: (Int) -> Unit,
    onSaveApkEvidence: () -> Unit,
    onDissectEntryInHex: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val clipboard = LocalClipboardManager.current

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .testTag("apk_forensics_list"),
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
                            text = "APK FULL INFO, UI DESIGN & BACKUP COPY",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = "APK-এর সকল তথ্য, ডিজাইন অ্যাসেট, সার্টিফিকেট ও ব্যাকআপ APK কপি",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        OutlinedButton(
                            onClick = onPickExternalApk,
                            modifier = Modifier.testTag("pick_external_apk_button"),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                        ) {
                            Icon(Icons.Default.FolderOpen, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Load APK", style = MaterialTheme.typography.labelLarge)
                        }
                        Button(
                            onClick = onSaveApkEvidence,
                            modifier = Modifier.testTag("save_apk_evidence_button"),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                        ) {
                            Icon(Icons.Default.BookmarkAdd, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Save", style = MaterialTheme.typography.labelLarge)
                        }
                    }
                }

                LazyRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.testTag("package_selector_row")
                ) {
                    items(packages, key = { it.packageName }) { pkg ->
                        FilterChip(
                            selected = pkg.packageName == selectedPackageName,
                            onClick = { onSelectPackage(pkg.packageName) },
                            label = {
                                Text(
                                    text = "${pkg.appLabel} (API ${pkg.targetSdk})",
                                    style = MaterialTheme.typography.labelLarge
                                )
                            },
                            leadingIcon = {
                                Icon(
                                    imageVector = Icons.Default.Android,
                                    contentDescription = null,
                                    modifier = Modifier.size(16.dp)
                                )
                            }
                        )
                    }
                }
            }
        }

        if (isLoading) {
            item {
                Box(modifier = Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
            }
        } else if (report != null) {
            item {
                ApkSummaryHeroCard(
                    report = report,
                    onCopyCert = { clipboard.setText(AnnotatedString(report.certSha256)) },
                    onBackupCopyApk = { onBackupCopyApk(report) },
                    onExplainWithAi = {
                        onExplainWithAi(
                            "APK: ${report.appLabel} (${report.packageName})",
                            "এই '${report.appLabel}' (${report.packageName}) APK-এর সকল তথ্য, ভেতরের UI/Design ফ্রেমওয়ার্ক (${report.designProfile.primaryUiFramework}), সিকিউরিটি স্কোর (${report.securityScore}/100), পারমিশন এবং কম্পোনেন্টগুলোর কাজ সহজ বাংলায় বিস্তারিত বুঝিয়ে বলো।"
                        )
                    }
                )
            }

            item {
                val tabs = listOf(
                    "All Info & Security",
                    "UI & Design (${report.designProfile.drawableAssetCount + report.designProfile.fontAssetCount})",
                    "Archive (${report.totalArchiveEntries})",
                    "Permissions (${report.permissions.size})",
                    "Components (${report.components.size})",
                    "DEX Header (${report.dexHeaderFields.size})"
                )
                ScrollableTabRow(
                    selectedTabIndex = subTab,
                    edgePadding = 0.dp,
                    containerColor = MaterialTheme.colorScheme.surface,
                    contentColor = MaterialTheme.colorScheme.primary,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .testTag("apk_sub_tabs")
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
                            },
                            modifier = Modifier.testTag("apk_subtab_$idx")
                        )
                    }
                }
            }

            when (subTab) {
                0 -> {
                    // Complete APK Metadata, OWASP MASVS Security Findings & Full X.509 Certificate
                    item {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                        ) {
                            Column(
                                modifier = Modifier.padding(14.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Text(
                                    text = "OWASP MASVS SECURITY POSTURE (${report.securityScore}/100 • ${report.securityGrade})",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.primary
                                )
                                report.securityFindings.forEach { finding ->
                                    val color = when (finding.severity) {
                                        "HIGH" -> MaterialTheme.colorScheme.error
                                        "MEDIUM" -> MaterialTheme.colorScheme.tertiary
                                        else -> MaterialTheme.colorScheme.primary
                                    }
                                    Row(
                                        verticalAlignment = Alignment.Top,
                                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Icon(
                                            imageVector = if (finding.severity == "PASS") Icons.Default.CheckCircle else Icons.Default.Warning,
                                            contentDescription = null,
                                            tint = color,
                                            modifier = Modifier.size(18.dp).padding(top = 2.dp)
                                        )
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(finding.title, style = MaterialTheme.typography.titleSmall, color = color)
                                            Text(finding.descriptionBn, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                        }
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
                            Column(
                                modifier = Modifier.padding(14.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Text(
                                    text = "COMPLETE APK & PACKAGE METADATA (সকল তথ্য)",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.secondary
                                )
                                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                                MetadataKeyValueRow("App Name & Package", "${report.appLabel} (${report.packageName})")
                                MetadataKeyValueRow("Version Name & Code", "v${report.versionName} (Build ${report.versionCode})")
                                MetadataKeyValueRow("SDK Compatibility", "minSdk ${report.minSdk} • targetSdk ${report.targetSdk}")
                                MetadataKeyValueRow("CPU Architectures (ABIs)", report.supportedAbis.joinToString(", "))
                                MetadataKeyValueRow("Base APK Path", report.sourceApkPath)
                                MetadataKeyValueRow("Data Sandbox Dir", report.dataDir)
                                MetadataKeyValueRow("Native Library Dir", report.nativeLibDir)
                                MetadataKeyValueRow("Linux Process UID", "${report.uid} (${if (report.isSystemApp) "System" else "User App"})")
                                MetadataKeyValueRow("First Install / Update", "${report.installDate} • ${report.lastUpdateDate}")
                            }
                        }
                    }

                    item {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                        ) {
                            Column(
                                modifier = Modifier.padding(14.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Text(
                                    text = "X.509 SIGNING CERTIFICATE DETAILS",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.primary
                                )
                                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                                MetadataKeyValueRow("Subject DN", report.certDetails.subjectDn)
                                MetadataKeyValueRow("Issuer DN", report.certDetails.issuerDn)
                                MetadataKeyValueRow("Signature Algorithm", report.certDetails.sigAlgName)
                                MetadataKeyValueRow("Serial Number", report.certDetails.serialNumberHex)
                                MetadataKeyValueRow("Validity Window", "${report.certDetails.validFrom} to ${report.certDetails.validUntil}")
                                MetadataKeyValueRow("SHA-256 Digest", report.certSha256)
                                MetadataKeyValueRow("MD5 Digest", report.certMd5)
                            }
                        }
                    }
                }

                1 -> {
                    // UI & Design System / Visual Assets Inspector
                    val dp = report.designProfile
                    item {
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .border(1.dp, MaterialTheme.colorScheme.primary, RoundedCornerShape(14.dp)),
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
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                                        modifier = Modifier.weight(1f)
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.Palette,
                                            contentDescription = null,
                                            tint = MaterialTheme.colorScheme.primary
                                        )
                                        Column {
                                            Text(
                                                text = "UI ARCHITECTURE & DESIGN SYSTEM",
                                                style = MaterialTheme.typography.labelSmall,
                                                color = MaterialTheme.colorScheme.secondary
                                            )
                                            Text(
                                                text = dp.primaryUiFramework,
                                                style = MaterialTheme.typography.titleMedium,
                                                color = MaterialTheme.colorScheme.onSurface
                                            )
                                        }
                                    }
                                    AssistChip(
                                        onClick = {
                                            onExplainWithAi(
                                                "UI & Design: ${report.appLabel}",
                                                "এই অ্যাপটির UI এবং Design সিস্টেমে কী কী ব্যবহার করা হয়েছে (${dp.primaryUiFramework}, Tech Stack: ${dp.detectedTechStack.joinToString()}, Fonts: ${dp.fontFiles.joinToString()})? কীভাবে এই ডিজাইন কাজ করে তা বাংলায় বুঝিয়ে বলো।"
                                            )
                                        },
                                        label = { Text("AI Design ব্যখ্যা", style = MaterialTheme.typography.labelMedium) },
                                        leadingIcon = {
                                            Icon(Icons.Default.AutoAwesome, contentDescription = null, modifier = Modifier.size(15.dp))
                                        }
                                    )
                                }

                                Text(
                                    text = "Detected Libraries & Design Features:",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )

                                FlowRow(
                                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                                    verticalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    dp.detectedTechStack.forEach { tech ->
                                        Surface(
                                            color = MaterialTheme.colorScheme.primaryContainer,
                                            shape = RoundedCornerShape(8.dp)
                                        ) {
                                            Text(
                                                text = tech,
                                                style = MaterialTheme.typography.labelMedium,
                                                color = MaterialTheme.colorScheme.primary,
                                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp)
                                            )
                                        }
                                    }
                                }

                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    ApkStatBox("LAYOUT XML", "${dp.layoutXmlCount} files", Modifier.weight(1f))
                                    ApkStatBox("DRAWABLES", "${dp.drawableAssetCount} icons/art", Modifier.weight(1f))
                                    ApkStatBox("FONTS / MIPMAP", "${dp.fontAssetCount} fonts • ${dp.mipmapIconCount} icons", Modifier.weight(1f))
                                }
                            }
                        }
                    }

                    if (dp.fontFiles.isNotEmpty()) {
                        item {
                            DesignAssetGroupCard(
                                title = "BUNDLED TYPOGRAPHY & FONTS (${dp.fontFiles.size})",
                                subtitle = "অ্যাপের ভেতরে থাকা কাস্টম ফন্ট ফাইল (Tap Hex to inspect)",
                                items = dp.fontFiles,
                                onDissectItem = { entryName ->
                                    onDissectEntryInHex("apk_entry:${report.sourceApkPath}::$entryName")
                                }
                            )
                        }
                    }

                    if (dp.layoutFiles.isNotEmpty()) {
                        item {
                            DesignAssetGroupCard(
                                title = "XML UI LAYOUTS & SCREENS (${dp.layoutXmlCount})",
                                subtitle = "অ্যাপের স্ক্রিন লেআউট এক্সএমএল রিসোর্স",
                                items = dp.layoutFiles,
                                onDissectItem = { entryName ->
                                    onDissectEntryInHex("apk_entry:${report.sourceApkPath}::$entryName")
                                }
                            )
                        }
                    }

                    if (dp.sampleDrawables.isNotEmpty()) {
                        item {
                            DesignAssetGroupCard(
                                title = "DRAWABLES, VECTORS & LAUNCHER ICONS (${dp.drawableAssetCount + dp.mipmapIconCount})",
                                subtitle = "অ্যাপের আইকন, ভেক্টর গ্রাফিক্স ও ইমেজ রিসোর্স",
                                items = dp.sampleDrawables,
                                onDissectItem = { entryName ->
                                    onDissectEntryInHex("apk_entry:${report.sourceApkPath}::$entryName")
                                }
                            )
                        }
                    }

                    if (dp.bundledAssets.isNotEmpty()) {
                        item {
                            DesignAssetGroupCard(
                                title = "RAW BUNDLED ASSETS (${dp.rawAssetCount})",
                                subtitle = "assets/ ফোল্ডারে থাকা কনফিগ, মডেল বা ওয়েব ফাইল",
                                items = dp.bundledAssets,
                                onDissectItem = { entryName ->
                                    onDissectEntryInHex("apk_entry:${report.sourceApkPath}::$entryName")
                                }
                            )
                        }
                    }
                }

                2 -> {
                    // APK Archive Structure & Direct Jump to Binary Dissector for ANY entry
                    items(report.keyEntries, key = { it.name }) { entry ->
                        ApkArchiveEntryCard(
                            entry = entry,
                            onDissect = {
                                onDissectEntryInHex("apk_entry:${report.sourceApkPath}::${entry.name}")
                            }
                        )
                    }
                }

                3 -> {
                    // Requested Permissions Audit
                    if (report.permissions.isEmpty()) {
                        item {
                            Text(
                                text = "Zero permissions requested in AndroidManifest.xml (Least-Privilege).",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.padding(16.dp)
                            )
                        }
                    } else {
                        items(report.permissions, key = { it.name }) { perm ->
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                        Row(
                                            verticalAlignment = Alignment.CenterVertically,
                                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                                        ) {
                                            Icon(
                                                imageVector = Icons.Default.Security,
                                                contentDescription = null,
                                                tint = if (perm.isSensitive) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                                                modifier = Modifier.size(16.dp)
                                            )
                                            Text(
                                                text = perm.shortName,
                                                style = MaterialTheme.typography.titleMedium,
                                                color = MaterialTheme.colorScheme.onSurface
                                            )
                                        }
                                        Text(
                                            text = perm.name,
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.secondary
                                        )
                                        Text(
                                            text = perm.description,
                                            style = MaterialTheme.typography.bodyMedium,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                    IconButton(
                                        onClick = {
                                            onExplainWithAi(
                                                "Permission: ${perm.shortName}",
                                                "অ্যান্ড্রয়েড পারমিশন '${perm.name}'-এর কাজ কী এবং এই অ্যাপটি কেন এটি ব্যবহার করছে বা এর ঝুঁকি কী তা বাংলায় বুঝিয়ে বলো।"
                                            )
                                        }
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.AutoAwesome,
                                            contentDescription = "Ask AI about permission",
                                            tint = MaterialTheme.colorScheme.primary,
                                            modifier = Modifier.size(18.dp)
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                4 -> {
                    // Components Attack Surface
                    items(report.components, key = { "${it.type}_${it.name}" }) { comp ->
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(12.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Text(
                                            text = comp.type.uppercase(),
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.secondary,
                                            modifier = Modifier
                                                .clip(RoundedCornerShape(4.dp))
                                                .background(MaterialTheme.colorScheme.secondaryContainer)
                                                .padding(horizontal = 6.dp, vertical = 2.dp)
                                        )
                                        Text(
                                            text = if (comp.isExported) "EXPORTED (PUBLIC IPC)" else "INTERNAL",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = if (comp.isExported) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.primary,
                                            modifier = Modifier
                                                .clip(RoundedCornerShape(4.dp))
                                                .background(
                                                    if (comp.isExported) MaterialTheme.colorScheme.tertiaryContainer
                                                    else MaterialTheme.colorScheme.primaryContainer
                                                )
                                                .padding(horizontal = 6.dp, vertical = 2.dp)
                                        )
                                    }
                                    Text(
                                        text = comp.name,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurface,
                                        modifier = Modifier.padding(top = 6.dp)
                                    )
                                }
                                IconButton(
                                    onClick = {
                                        onExplainWithAi(
                                            "${comp.type}: ${comp.name.substringAfterLast('.')}",
                                            "অ্যাপের এই ${comp.type} কম্পোনেন্ট '${comp.name}' (Exported=${comp.isExported})-এর কাজ কী তা বাংলায় বুঝিয়ে বলো।"
                                        )
                                    }
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.AutoAwesome,
                                        contentDescription = "Ask AI about component",
                                        tint = MaterialTheme.colorScheme.primary,
                                        modifier = Modifier.size(18.dp)
                                    )
                                }
                            }
                        }
                    }
                }

                5 -> {
                    // Primary DEX Header Breakdown
                    items(report.dexHeaderFields, key = { it.name }) { field ->
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                        ) {
                            Column(
                                modifier = Modifier.padding(12.dp),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                                    Text(field.name, style = MaterialTheme.typography.titleMedium)
                                    Text(
                                        field.offsetRange,
                                        style = MaterialTheme.typography.labelMedium,
                                        color = MaterialTheme.colorScheme.secondary
                                    )
                                }
                                Text(field.decodedValue, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary)
                                Text("Raw: ${field.rawHex}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ApkSummaryHeroCard(
    report: ApkAuditReport,
    onCopyCert: () -> Unit,
    onBackupCopyApk: () -> Unit,
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
                    Text(report.appLabel, style = MaterialTheme.typography.titleLarge)
                    Text(
                        text = "${report.packageName} • v${report.versionName} (${report.versionCode})",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.secondary
                    )
                }
                Surface(
                    color = if (report.securityScore >= 80) MaterialTheme.colorScheme.primaryContainer
                    else MaterialTheme.colorScheme.tertiaryContainer,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(
                        text = "SCORE ${report.securityScore}/100",
                        style = MaterialTheme.typography.labelMedium,
                        color = if (report.securityScore >= 80) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.tertiary,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                ApkStatBox("SDK TARGET", "min ${report.minSdk} / api ${report.targetSdk}", Modifier.weight(1f))
                ApkStatBox("DEX / .SO", "${report.dexCount} DEX • ${report.nativeSoCount} .so", Modifier.weight(1f))
                ApkStatBox("APK SIZE", "${report.apkSizeBytes / 1024} KB", Modifier.weight(1f))
            }

            // Action Buttons: Backup Copy APK + Explain with AI
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = onBackupCopyApk,
                    modifier = Modifier
                        .weight(1f)
                        .testTag("backup_copy_apk_button"),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                ) {
                    Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("কপি APK (Save Copy)", style = MaterialTheme.typography.labelLarge)
                }
                OutlinedButton(
                    onClick = onExplainWithAi,
                    modifier = Modifier
                        .weight(1f)
                        .testTag("apk_explain_ai_button"),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                ) {
                    Icon(Icons.Default.AutoAwesome, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("AI দিয়ে সব বুঝুন", style = MaterialTheme.typography.labelLarge)
                }
            }

            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(
                        imageVector = Icons.Default.VerifiedUser,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                    Column {
                        Text(
                            text = "UI DESIGN: ${report.designProfile.primaryUiFramework.uppercase()}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = "SHA-256: ${report.certSha256}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
                IconButton(onClick = onCopyCert) {
                    Icon(
                        imageVector = Icons.Default.ContentCopy,
                        contentDescription = "Copy Certificate SHA-256",
                        modifier = Modifier.size(16.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun MetadataKeyValueRow(
    label: String,
    value: String
) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
            text = value,
            fontFamily = JetBrainsMonoFontFamily,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}

@Composable
private fun DesignAssetGroupCard(
    title: String,
    subtitle: String,
    items: List<String>,
    onDissectItem: (String) -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(title, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            items.forEach { path ->
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = path,
                        fontFamily = JetBrainsMonoFontFamily,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.weight(1f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    AssistChip(
                        onClick = { onDissectItem(path) },
                        label = { Text("Hex", style = MaterialTheme.typography.labelSmall) }
                    )
                }
            }
        }
    }
}

@Composable
private fun ApkStatBox(
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
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurface, maxLines = 1)
    }
}

@Composable
private fun ApkArchiveEntryCard(
    entry: ApkEntrySummary,
    onDissect: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = entry.category,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier
                            .clip(RoundedCornerShape(4.dp))
                            .background(MaterialTheme.colorScheme.primaryContainer)
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                    Text(
                        text = entry.name,
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                Text(
                    text = "Raw: ${entry.uncompressedBytes} B • Compressed: ${entry.compressedBytes} B • CRC32: ${entry.crcHex}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            AssistChip(
                onClick = onDissect,
                label = { Text("Hex/Dissect", style = MaterialTheme.typography.labelMedium) },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Default.Terminal,
                        contentDescription = null,
                        modifier = Modifier.size(14.dp)
                    )
                }
            )
        }
    }
}
