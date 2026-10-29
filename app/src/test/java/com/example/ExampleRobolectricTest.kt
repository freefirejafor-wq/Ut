package com.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.example.analyzer.ApkPackageInspector
import com.example.analyzer.BinaryAnalyzer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleRobolectricTest {

    @Test
    fun `read app_name from context and verify BinaryAnalyzer DEX and YARA detection`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val appName = context.getString(R.string.app_name)
        assertEquals("REA Inspector", appName)

        // Verify real DEX magic header detection ("dex\n035\0") and YARA signature scanner
        val sampleDex = byteArrayOf(
            0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00,
            0x12, 0x34, 0x56, 0x78, 0x41, 0x42, 0x43, 0x44
        ) + "Java_com_example_NativeBridge_init\u0000https://api.github.com/repos/morluto/rea\u0000".toByteArray()

        val analysis = BinaryAnalyzer.analyzeBytes(
            sourceName = "classes.dex",
            sourcePath = "/data/app/classes.dex",
            fullSizeBytes = sampleDex.size.toLong(),
            bytes = sampleDex,
            minStringLength = 4
        )
        assertEquals("DEX", analysis.formatBadge)
        assertTrue(analysis.magicHex.startsWith("64 65 78 0A"))
        assertTrue(analysis.signatureMatches.any { it.ruleId == "YARA_ANDROID_DEX_HEADER" })
        assertTrue(analysis.signatureMatches.any { it.ruleId == "YARA_JNI_BRIDGE_SYMBOL" })

        val apkReport = ApkPackageInspector.inspectPackage(context, context.packageName)
        assertNotNull(apkReport.designProfile)
        assertTrue(apkReport.securityScore in 25..100)
    }
}
