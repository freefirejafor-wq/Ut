package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Psychology
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.ui.AiAnalystUiState
import com.example.ui.AiChatEntry

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun AiAnalystScreen(
    promptInput: String,
    activeTopic: String,
    aiState: AiAnalystUiState,
    history: List<AiChatEntry>,
    onPromptChange: (String) -> Unit,
    onAskAi: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val clipboard = LocalClipboardManager.current

    val quickPrompts = listOf(
        "APK-এর সকল তথ্য ও ডিজাইন বুঝাও" to "বর্তমান APK-এর সকল তথ্য, ভেতরের UI/Design ফ্রেমওয়ার্ক, ফন্ট, অ্যাসেট এবং সিকিউরিটি স্কোর বিস্তারিত বাংলায় বুঝিয়ে বলো।",
        "Binary / DEX ফাইলের কাজ কী?" to "বর্তমান লোড করা Binary বা classes.dex ফাইলটির কাজ কী, এর Magic Header, Entropy এবং YARA সিগনেচারগুলোর মানে সহজ বাংলায় বুঝিয়ে বলো।",
        "পারমিশন ও কম্পোনেন্ট ঝুঁকি" to "এই অ্যাপে কী কী Permission এবং Exported Component আছে? কোনটার কাজ কী এবং কোনো সিকিউরিটি ঝুঁকি আছে কি না তা বুঝিয়ে বলো।",
        "Web ও API ট্রেস বিশ্লেষণ" to "বর্তমান Web/API Trace-এর HTTP হেডার, TLS হ্যান্ডশেক এবং সিকিউরিটি হেডারগুলোর (CSP, HSTS) কাজ কী তা বিশ্লেষণ করো।",
        "কোন ট্যাবের কাজ কী? (গাইড)" to "REA Inspector অ্যাপের প্রতিটি টুল (Binary & Hex, APK & Design, Web Tracer, APK Backup Copy, Vault) কীভাবে কাজ করে এবং কোনটার কাজ কী তা ধাপে ধাপে বুঝিয়ে দাও।"
    )

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .testTag("ai_analyst_list"),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, MaterialTheme.colorScheme.primary, RoundedCornerShape(16.dp)),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Surface(
                            color = MaterialTheme.colorScheme.primaryContainer,
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.AutoAwesome,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier
                                    .padding(8.dp)
                                    .size(22.dp)
                            )
                        }
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "AI FORENSIC EXPLAINER (GEMINI 3.8)",
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.primary
                            )
                            Text(
                                text = "কোনটার কাজ কী, APK ডিজাইন ও বাইনারি সহজ বাংলায় বুঝুন",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    Surface(
                        color = MaterialTheme.colorScheme.background,
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = "Active Context: $activeTopic",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.secondary,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
                        )
                    }

                    Text(
                        text = "এক ক্লিকে প্রশ্ন করুন (Quick Explain Prompts):",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        quickPrompts.forEachIndexed { idx, (shortLabel, fullQuestion) ->
                            AssistChip(
                                onClick = { onAskAi(fullQuestion) },
                                label = { Text(shortLabel, style = MaterialTheme.typography.labelMedium) },
                                leadingIcon = {
                                    Icon(
                                        imageVector = Icons.Default.Psychology,
                                        contentDescription = null,
                                        modifier = Modifier.size(16.dp)
                                    )
                                },
                                modifier = Modifier.testTag("ai_quick_prompt_$idx")
                            )
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        OutlinedTextField(
                            value = promptInput,
                            onValueChange = onPromptChange,
                            placeholder = { Text("যেকোনো হেডার, ডেক্স, পারমিশন বা APK সম্পর্কে প্রশ্ন লিখুন…") },
                            modifier = Modifier
                                .weight(1f)
                                .testTag("ai_prompt_input")
                        )
                        Button(
                            onClick = { onAskAi(promptInput) },
                            enabled = aiState !is AiAnalystUiState.Loading && aiState !is AiAnalystUiState.Streaming && promptInput.isNotBlank(),
                            modifier = Modifier
                                .height(54.dp)
                                .testTag("ai_send_button")
                        ) {
                            Icon(Icons.AutoMirrored.Filled.Send, contentDescription = "Ask AI")
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("বুঝাও")
                        }
                    }
                }
            }
        }

        // Live Streaming / Loading / Error Response Card
        when (aiState) {
            is AiAnalystUiState.Loading -> {
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
                            horizontalArrangement = Arrangement.spacedBy(14.dp)
                        ) {
                            CircularProgressIndicator(modifier = Modifier.size(26.dp))
                            Column {
                                Text(
                                    text = "AI ফরেনসিক ডেটা বিশ্লেষণ করছে…",
                                    style = MaterialTheme.typography.titleSmall,
                                    color = MaterialTheme.colorScheme.primary
                                )
                                Text(
                                    text = "APK, DEX বাইনারি ও সিকিউরিটি কনটেক্সট মিলিয়ে সহজ বাংলায় ব্যাখ্যা তৈরি হচ্ছে",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }

            is AiAnalystUiState.Streaming -> {
                item {
                    AiResponseCard(
                        title = "লাইভ এআই বিশ্লেষণ (Streaming…)",
                        contextBadge = activeTopic,
                        responseText = aiState.partialText,
                        isStreaming = true,
                        onCopy = { clipboard.setText(AnnotatedString(aiState.partialText)) }
                    )
                }
            }

            is AiAnalystUiState.Error -> {
                item {
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(1.dp, MaterialTheme.colorScheme.error, RoundedCornerShape(12.dp)),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(14.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.ErrorOutline,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.error
                            )
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "AI সংযোগ বা বিশ্লেষণে সমস্যা হয়েছে",
                                    style = MaterialTheme.typography.titleSmall,
                                    color = MaterialTheme.colorScheme.onErrorContainer
                                )
                                Text(
                                    text = aiState.errorMessage,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onErrorContainer
                                )
                            }
                        }
                    }
                }
            }

            else -> Unit
        }

        // Previous AI Explanations History
        if (history.isNotEmpty()) {
            item {
                Text(
                    text = "AI EXPLANATION LOG (${history.size})",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.secondary
                )
            }
            items(history, key = { it.id }) { entry ->
                AiResponseCard(
                    title = entry.userPrompt,
                    contextBadge = entry.contextLabel,
                    responseText = entry.aiResponse,
                    isStreaming = false,
                    onCopy = { clipboard.setText(AnnotatedString(entry.aiResponse)) }
                )
            }
        }

        // Built-in Feature Reference Card (Always available offline & online)
        item {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(14.dp)),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text(
                        text = "কোনটার কাজ কী? — ফরেনসিক রেফারেন্স গাইড",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    FeatureExplainRow(
                        term = "classes.dex (Dalvik Executable)",
                        desc = "অ্যান্ড্রয়েড অ্যাপের সব Java/Kotlin সোর্স কোড কম্পাইল হয়ে এই ফাইলে থাকে। এতে Class, Method ও String পুল থাকে।"
                    )
                    FeatureExplainRow(
                        term = "lib/*.so (Native ELF64 Binary)",
                        desc = "C/C++ দিয়ে তৈরি মেশিন কোড লাইব্রেরি (ARM64/x86)। গেম ইঞ্জিন, ক্রিপ্টোগ্রাফি বা হাই-পারফরম্যান্স কাজের জন্য ব্যবহৃত হয়।"
                    )
                    FeatureExplainRow(
                        term = "AndroidManifest.xml (AXML) ও resources.arsc",
                        desc = "অ্যাপের নাম, পারমিশন, Activity/Service তালিকা এবং UI ডিজাইন/স্ট্রিং আইডি টেবিল এই ফাইলগুলোতে বাইনারি আকারে থাকে।"
                    )
                    FeatureExplainRow(
                        term = "Shannon Entropy (0.0 – 8.0 bits/byte)",
                        desc = "বাইনারি ডেটার র‍্যান্ডমনেস মাপে। ৭.২-এর বেশি হলে বুঝতে হবে ফাইলটি এনক্রিপ্টেড, কমপ্রেসড বা প্যাকার দিয়ে লুকানো।"
                    )
                    FeatureExplainRow(
                        term = "APK Design Profile & Backup Copy",
                        desc = "APK ট্যাবে অ্যাপটি Jetpack Compose, XML নাকি Flutter দিয়ে তৈরি, কয়টি ফন্ট/আইকন আছে তা দেখা যায় এবং মূল APK-এর ব্যাকআপ কপি সেভ করা যায়।"
                    )
                }
            }
        }
    }
}

@Composable
private fun AiResponseCard(
    title: String,
    contextBadge: String,
    responseText: String,
    isStreaming: Boolean,
    onCopy: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(
                width = 1.dp,
                color = if (isStreaming) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline,
                shape = RoundedCornerShape(14.dp)
            ),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = contextBadge,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.secondary,
                        modifier = Modifier
                            .clip(RoundedCornerShape(4.dp))
                            .background(MaterialTheme.colorScheme.secondaryContainer)
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = title,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
                IconButton(onClick = onCopy) {
                    Icon(
                        imageVector = Icons.Default.ContentCopy,
                        contentDescription = "Copy AI explanation",
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Text(
                text = responseText,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
        }
    }
}

@Composable
private fun FeatureExplainRow(
    term: String,
    desc: String
) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(
            text = "• $term",
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.secondary
        )
        Text(
            text = desc,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 10.dp)
        )
    }
}
