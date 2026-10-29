package com.example.analyzer

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.EventListener
import okhttp3.Handshake
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.concurrent.TimeUnit

data class SecurityHeaderAudit(
    val headerName: String,
    val isPresent: Boolean,
    val valueOrWarning: String,
    val purpose: String
)

data class WebTraceResult(
    val targetUrl: String,
    val finalUrl: String,
    val requestMethod: String,
    val statusCode: Int,
    val statusMessage: String,
    val protocol: String,
    val tlsVersion: String,
    val cipherSuite: String,
    val tlsCertificateChain: List<String>,
    val dnsDurationMs: Long,
    val connectDurationMs: Long,
    val tlsDurationMs: Long,
    val totalDurationMs: Long,
    val contentType: String,
    val contentLengthBytes: Long,
    val responseHeaders: List<Pair<String, String>>,
    val securityAudit: List<SecurityHeaderAudit>,
    val discoveredEndpoints: List<String>,
    val discoveredScriptsAndKeys: List<String>,
    val payloadPreview: String,
    val curlSnippet: String,
    val kotlinOkHttpSnippet: String,
    val pythonRequestsSnippet: String,
    val jsFetchSnippet: String,
    val errorMessage: String? = null
)

object WebBehaviorTracer {

    val presetEndpoints = listOf(
        "https://api.github.com/repos/morluto/rea" to "GitHub API: morluto/rea Repo Metadata",
        "https://github.com/morluto/rea" to "GitHub Web DOM: morluto/rea HTML & Scripts",
        "https://httpbin.org/get" to "HTTPBin: Live Request & Header Echo",
        "https://www.google.com" to "Google: HTTP/2 + TLSv1.3 Security Audit"
    )

    val supportedMethods = listOf("GET", "POST", "PUT", "DELETE", "HEAD")

    suspend fun traceUrl(
        rawUrl: String,
        method: String = "GET",
        customHeadersText: String = "",
        requestBodyText: String = ""
    ): WebTraceResult = withContext(Dispatchers.IO) {
        val normalizedUrl = if (
            !rawUrl.startsWith("http://", ignoreCase = true) &&
            !rawUrl.startsWith("https://", ignoreCase = true)
        ) {
            "https://${rawUrl.trim()}"
        } else {
            rawUrl.trim()
        }

        val cleanMethod = method.uppercase().ifBlank { "GET" }

        var dnsStart = 0L
        var dnsMs = 0L
        var connectStart = 0L
        var connectMs = 0L
        var tlsStart = 0L
        var tlsMs = 0L

        val eventListener = object : EventListener() {
            override fun dnsStart(call: Call, domainName: String) {
                dnsStart = System.nanoTime()
            }

            override fun dnsEnd(call: Call, domainName: String, inetAddressList: List<InetAddress>) {
                if (dnsStart > 0L) {
                    dnsMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - dnsStart)
                }
            }

            override fun connectStart(call: Call, inetSocketAddress: InetSocketAddress, proxy: Proxy) {
                connectStart = System.nanoTime()
            }

            override fun secureConnectStart(call: Call) {
                tlsStart = System.nanoTime()
            }

            override fun secureConnectEnd(call: Call, handshake: Handshake?) {
                if (tlsStart > 0L) {
                    tlsMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - tlsStart)
                }
            }

            override fun connectEnd(
                call: Call,
                inetSocketAddress: InetSocketAddress,
                proxy: Proxy,
                protocol: Protocol?
            ) {
                if (connectStart > 0L) {
                    connectMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - connectStart)
                }
            }

            override fun connectFailed(
                call: Call,
                inetSocketAddress: InetSocketAddress,
                proxy: Proxy,
                protocol: Protocol?,
                ioe: IOException
            ) {
                if (connectStart > 0L) {
                    connectMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - connectStart)
                }
            }
        }

        val client = OkHttpClient.Builder()
            .connectTimeout(12, TimeUnit.SECONDS)
            .readTimeout(12, TimeUnit.SECONDS)
            .followRedirects(true)
            .eventListener(eventListener)
            .build()

        val parsedCustomHeaders = parseCustomHeaders(customHeadersText)

        val reqBuilder = Request.Builder()
            .url(normalizedUrl)
            .header("User-Agent", "REA-Inspector-Android/2.0 (Evidence-Based Reverse Engineering)")
            .header("Accept", "application/json, text/html, */*")

        parsedCustomHeaders.forEach { (k, v) ->
            reqBuilder.header(k, v)
        }

        when (cleanMethod) {
            "POST", "PUT" -> {
                val mediaType = "application/json; charset=utf-8".toMediaTypeOrNull()
                val bodyPayload = requestBodyText.ifBlank { "{}" }.toRequestBody(mediaType)
                reqBuilder.method(cleanMethod, bodyPayload)
            }
            "DELETE" -> {
                if (requestBodyText.isNotBlank()) {
                    val mediaType = "application/json; charset=utf-8".toMediaTypeOrNull()
                    reqBuilder.delete(requestBodyText.toRequestBody(mediaType))
                } else {
                    reqBuilder.delete()
                }
            }
            "HEAD" -> reqBuilder.head()
            else -> reqBuilder.get()
        }

        val request = reqBuilder.build()
        val callStart = System.nanoTime()

        try {
            client.newCall(request).execute().use { response ->
                val bodyString = if (cleanMethod == "HEAD") {
                    "(HEAD request — response headers only, no body transferred)"
                } else {
                    response.body?.string()?.take(24_000) ?: ""
                }
                val totalMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - callStart)
                val handshake = response.handshake
                val tlsVersion = handshake?.tlsVersion?.javaName ?: "Plain HTTP / None"
                val cipherSuite = handshake?.cipherSuite?.javaName ?: "N/A"
                val protocol = response.protocol.toString().uppercase()

                val dateFmt = SimpleDateFormat("yyyy-MM-dd", Locale.US)
                val tlsCerts = handshake?.peerCertificates?.mapIndexed { idx, cert ->
                    val x509 = cert as? X509Certificate
                    if (x509 != null) {
                        "#$idx Subject: ${x509.subjectX500Principal.name} | Issuer: ${x509.issuerX500Principal.name} | Valid: ${dateFmt.format(x509.notBefore)}..${dateFmt.format(x509.notAfter)} (${x509.sigAlgName})"
                    } else {
                        "#$idx ${cert.type} Certificate"
                    }
                } ?: emptyList()

                val headersList = mutableListOf<Pair<String, String>>()
                val headers = response.headers
                for (i in 0 until headers.size) {
                    headersList.add(headers.name(i) to headers.value(i))
                }

                val securityAudit = auditSecurityHeaders(headersList.toMap())
                val discoveredEndpoints = extractEndpointsFromBody(bodyString)
                val discoveredScriptsAndKeys = extractScriptsAndJsonKeys(bodyString)

                val contentType = response.header("Content-Type") ?: "unknown"
                val contentLength = response.body?.contentLength()?.takeIf { it >= 0 }
                    ?: bodyString.toByteArray().size.toLong()

                WebTraceResult(
                    targetUrl = normalizedUrl,
                    finalUrl = response.request.url.toString(),
                    requestMethod = cleanMethod,
                    statusCode = response.code,
                    statusMessage = response.message.ifEmpty { "OK" },
                    protocol = protocol,
                    tlsVersion = tlsVersion,
                    cipherSuite = cipherSuite,
                    tlsCertificateChain = tlsCerts,
                    dnsDurationMs = dnsMs,
                    connectDurationMs = connectMs,
                    tlsDurationMs = tlsMs,
                    totalDurationMs = totalMs,
                    contentType = contentType,
                    contentLengthBytes = contentLength,
                    responseHeaders = headersList,
                    securityAudit = securityAudit,
                    discoveredEndpoints = discoveredEndpoints,
                    discoveredScriptsAndKeys = discoveredScriptsAndKeys,
                    payloadPreview = bodyString.take(2800),
                    curlSnippet = buildCurlSnippet(normalizedUrl, cleanMethod, parsedCustomHeaders, requestBodyText, headersList),
                    kotlinOkHttpSnippet = buildKotlinSnippet(normalizedUrl, cleanMethod, parsedCustomHeaders, requestBodyText),
                    pythonRequestsSnippet = buildPythonSnippet(normalizedUrl, cleanMethod, parsedCustomHeaders, requestBodyText),
                    jsFetchSnippet = buildJsFetchSnippet(normalizedUrl, cleanMethod, parsedCustomHeaders, requestBodyText),
                    errorMessage = null
                )
            }
        } catch (e: Exception) {
            val totalMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - callStart)
            WebTraceResult(
                targetUrl = normalizedUrl,
                finalUrl = normalizedUrl,
                requestMethod = cleanMethod,
                statusCode = 0,
                statusMessage = "Connection Error",
                protocol = "N/A",
                tlsVersion = "N/A",
                cipherSuite = "N/A",
                tlsCertificateChain = emptyList(),
                dnsDurationMs = dnsMs,
                connectDurationMs = connectMs,
                tlsDurationMs = tlsMs,
                totalDurationMs = totalMs,
                contentType = "N/A",
                contentLengthBytes = 0L,
                responseHeaders = emptyList(),
                securityAudit = emptyList(),
                discoveredEndpoints = emptyList(),
                discoveredScriptsAndKeys = emptyList(),
                payloadPreview = "",
                curlSnippet = buildCurlSnippet(normalizedUrl, cleanMethod, parsedCustomHeaders, requestBodyText, emptyList()),
                kotlinOkHttpSnippet = buildKotlinSnippet(normalizedUrl, cleanMethod, parsedCustomHeaders, requestBodyText),
                pythonRequestsSnippet = buildPythonSnippet(normalizedUrl, cleanMethod, parsedCustomHeaders, requestBodyText),
                jsFetchSnippet = buildJsFetchSnippet(normalizedUrl, cleanMethod, parsedCustomHeaders, requestBodyText),
                errorMessage = "${e.javaClass.simpleName}: ${e.localizedMessage ?: "Failed to reach endpoint"}"
            )
        }
    }

    private fun parseCustomHeaders(raw: String): List<Pair<String, String>> {
        if (raw.isBlank()) return emptyList()
        return raw.lines()
            .mapNotNull { line ->
                val idx = line.indexOf(':')
                if (idx > 0) {
                    val k = line.substring(0, idx).trim()
                    val v = line.substring(idx + 1).trim()
                    if (k.isNotEmpty() && v.isNotEmpty()) k to v else null
                } else null
            }
    }

    private fun auditSecurityHeaders(headerMap: Map<String, String>): List<SecurityHeaderAudit> {
        val lowerMap = headerMap.entries.associate { it.key.lowercase() to it.value }
        val checks = listOf(
            Triple("Strict-Transport-Security", "strict-transport-security", "Enforces HTTPS & prevents TLS downgrade attacks (HTTPS বাধ্যতামূলক করে)"),
            Triple("Content-Security-Policy", "content-security-policy", "Restricts XSS script execution & frame origins (XSS স্ক্রিপ্ট আক্রমণ রোধ করে)"),
            Triple("X-Frame-Options", "x-frame-options", "Prevents clickjacking via iframe embedding (ক্লিকজ্যাকিং প্রতিরোধ করে)"),
            Triple("X-Content-Type-Options", "x-content-type-options", "Prevents MIME-sniffing of response payloads (MIME স্নিফিং বন্ধ করে)"),
            Triple("Access-Control-Allow-Origin", "access-control-allow-origin", "Defines cross-origin resource sharing (CORS) policy"),
            Triple("Server", "server", "Reveals backend web server or reverse proxy technology (সার্ভার টেকনোলজি প্রকাশ করে)")
        )

        return checks.map { (title, key, purpose) ->
            val value = lowerMap[key]
            SecurityHeaderAudit(
                headerName = title,
                isPresent = value != null,
                valueOrWarning = value ?: "Missing in HTTP response",
                purpose = purpose
            )
        }
    }

    private fun extractEndpointsFromBody(body: String): List<String> {
        val regex = Regex("""https?://[a-zA-Z0-9._/~:-]+|/[a-zA-Z0-9_-]+/[a-zA-Z0-9._/-]+""")
        return regex.findAll(body)
            .map { it.value.trimEnd('.', ',', '"', '\'', ')', ']') }
            .filter { it.length in 8..110 && !it.startsWith("//") }
            .distinct()
            .take(25)
            .toList()
    }

    private fun extractScriptsAndJsonKeys(body: String): List<String> {
        val items = mutableListOf<String>()
        val scriptRegex = Regex("""<script[^>]+src=["']([^"']+)["']""", RegexOption.IGNORE_CASE)
        scriptRegex.findAll(body).forEach { m ->
            items.add("[SCRIPT] ${m.groupValues[1]}")
        }
        val jsonKeyRegex = Regex(""""([a-zA-Z0-9_]{3,32})"\s*:""")
        jsonKeyRegex.findAll(body).map { it.groupValues[1] }.distinct().take(20).forEach { key ->
            items.add("[JSON_KEY] \"$key\"")
        }
        return items.distinct().take(25)
    }

    private fun buildCurlSnippet(
        url: String,
        method: String,
        customHeaders: List<Pair<String, String>>,
        bodyText: String,
        responseHeaders: List<Pair<String, String>>
    ): String {
        val serverHeader = responseHeaders.firstOrNull { it.first.equals("server", ignoreCase = true) }?.second
        return buildString {
            appendLine("# Reconstructed by REA Inspector v2.0")
            if (serverHeader != null) appendLine("# Target Server: $serverHeader")
            appendLine("curl -i -X $method \\")
            appendLine("  '$url' \\")
            appendLine("  -H 'User-Agent: REA-Inspector-Android/2.0' \\")
            customHeaders.forEach { (k, v) ->
                appendLine("  -H '$k: $v' \\")
            }
            if ((method == "POST" || method == "PUT") && bodyText.isNotBlank()) {
                appendLine("  -H 'Content-Type: application/json' \\")
                append("  -d '${bodyText.replace("'", "\\'")}'")
            } else {
                append("  -H 'Accept: application/json, text/html, */*'")
            }
        }
    }

    private fun buildKotlinSnippet(
        url: String,
        method: String,
        customHeaders: List<Pair<String, String>>,
        bodyText: String
    ): String {
        val headersBlock = customHeaders.joinToString("\n") { (k, v) ->
            "    .header(\"$k\", \"$v\")"
        }
        val methodLine = if (method == "POST" || method == "PUT") {
            ".method(\"$method\", \"\"\"${bodyText.ifBlank { "{}" }}\"\"\".toRequestBody(\"application/json\".toMediaType()))"
        } else {
            ".method(\"$method\", null)"
        }
        return buildString {
            appendLine("val client = OkHttpClient()")
            appendLine("val request = Request.Builder()")
            appendLine("    .url(\"$url\")")
            appendLine("    .header(\"Accept\", \"application/json, text/html\")")
            if (headersBlock.isNotBlank()) appendLine(headersBlock)
            appendLine("    $methodLine")
            appendLine("    .build()")
            appendLine("client.newCall(request).execute().use { response ->")
            appendLine("    println(\"Status: \${response.code} Protocol: \${response.protocol}\")")
            append("    println(response.body?.string())\n}")
        }
    }

    private fun buildPythonSnippet(
        url: String,
        method: String,
        customHeaders: List<Pair<String, String>>,
        bodyText: String
    ): String {
        val hdrEntries = (listOf("User-Agent" to "REA-Inspector-Android/2.0") + customHeaders)
            .joinToString(",\n    ") { (k, v) -> "\"$k\": \"$v\"" }
        return buildString {
            appendLine("import requests")
            appendLine()
            appendLine("url = \"$url\"")
            appendLine("headers = {\n    $hdrEntries\n}")
            if ((method == "POST" || method == "PUT") && bodyText.isNotBlank()) {
                appendLine("payload = '''$bodyText'''")
                appendLine("response = requests.request(\"$method\", url, headers=headers, data=payload, timeout=12)")
            } else {
                appendLine("response = requests.request(\"$method\", url, headers=headers, timeout=12)")
            }
            appendLine("print(f\"Status: {response.status_code}\")")
            append("print(response.text[:1000])")
        }
    }

    private fun buildJsFetchSnippet(
        url: String,
        method: String,
        customHeaders: List<Pair<String, String>>,
        bodyText: String
    ): String {
        val hdrEntries = (listOf("Accept" to "application/json, text/html") + customHeaders)
            .joinToString(",\n    ") { (k, v) -> "\"$k\": \"$v\"" }
        return buildString {
            appendLine("const response = await fetch(\"$url\", {")
            appendLine("  method: \"$method\",")
            appendLine("  headers: {\n    $hdrEntries\n  }${if ((method == "POST" || method == "PUT") && bodyText.isNotBlank()) ",\n  body: JSON.stringify($bodyText)" else ""}")
            appendLine("});")
            appendLine("console.log(\"Status:\", response.status);")
            append("console.log(await response.text());")
        }
    }
}
