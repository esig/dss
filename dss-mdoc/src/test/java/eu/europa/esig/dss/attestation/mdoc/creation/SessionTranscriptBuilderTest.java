/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.COSEConstants;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.enumerations.EllipticCurve;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionTranscriptBuilderTest {

    @Test
    void dssDocumentTest() throws Exception {
        PublicKey deviceKey = generateKey();
        PublicKey readerKey = generateKey();

        byte[] select = new byte[]{0x01, 0x02};
        byte[] request = new byte[]{0x03, 0x04};

        SessionTranscriptBuilder builder =
                SessionTranscriptBuilder.nfcHandover(select, request)
                        .security(EllipticCurve.P_256, deviceKey)
                        .eReaderKey(readerKey);

        DSSDocument document = builder.build();
        CBORValue cborValue = builder.buildCbor();
        assertArrayEquals(DSSUtils.toByteArray(document), CBORUtils.serializeCbor(cborValue));

        SessionTranscriptBuilder builder2 =
                SessionTranscriptBuilder.nfcHandover(select, request)
                        .security(EllipticCurve.P_256, deviceKey)
                        .eReaderKey(readerKey);

        DSSDocument document2 = builder2.build();
        CBORValue cborValue2 = builder2.buildCbor();
        assertArrayEquals(DSSUtils.toByteArray(document), CBORUtils.serializeCbor(cborValue));
        assertArrayEquals(DSSUtils.toByteArray(document), DSSUtils.toByteArray(document2));
        assertArrayEquals(CBORUtils.serializeCbor(cborValue2), CBORUtils.serializeCbor(cborValue2));
    }

    @Test
    void nfcSessionTranscript() throws Exception {
        PublicKey deviceKey = generateKey();
        PublicKey readerKey = generateKey();

        byte[] select = new byte[]{0x01, 0x02};
        byte[] request = new byte[]{0x03, 0x04};

        SessionTranscriptBuilder builder =
                SessionTranscriptBuilder.nfcHandover(select, request)
                        .security(EllipticCurve.P_256, deviceKey)
                        .eReaderKey(readerKey);

        CBORValue result = builder.buildCbor();
        List<CBORValue> resultList = result.getElements();
        assertEquals(3, resultList.size());

        CBORValue deviceEngagementBytes = resultList.get(0);
        assertTrue(deviceEngagementBytes.isTag());
        assertEquals(24L, deviceEngagementBytes.getTag().longValue());
        assertTrue(deviceEngagementBytes.getTaggedValue().isByteString());

        CBORValue readerKeyBytes = resultList.get(1);
        assertTrue(readerKeyBytes.isTag());
        assertEquals(24L, readerKeyBytes.getTag().longValue());
        assertTrue(readerKeyBytes.getTaggedValue().isByteString());

        CBORValue readerKeyCbor = CBORUtils.parseCbor(readerKeyBytes.getTaggedValue().asBytes());

        assertEquals(COSEConstants.COSE_KEY_TYPE_EC2_VALUE,
                readerKeyCbor.get(COSEConstants.COSE_KEY_KTY).asInteger().longValue());

        assertEquals(EllipticCurve.P_256.getCOSEValue(),
                readerKeyCbor.get(COSEConstants.COSE_KEY_TYPE_EC2_CRV).asInteger().longValue());

        CBORValue handover = resultList.get(2);
        assertNotNull(handover);
        assertTrue(handover.isArray());

        assertEquals(2, handover.size());
        assertArrayEquals(select, handover.get(0).asBytes());
        assertArrayEquals(request, handover.get(1).asBytes());
    }

    @Test
    void nfcStaticHandover() throws Exception {
        PublicKey deviceKey = generateKey();
        PublicKey readerKey = generateKey();

        byte[] select = new byte[]{0x01};

        SessionTranscriptBuilder builder =
                SessionTranscriptBuilder.nfcStaticHandover(select)
                        .security(EllipticCurve.P_256, deviceKey)
                        .eReaderKey(readerKey);

        CBORValue result = builder.buildCbor();

        assertTrue(result.isArray());
        assertEquals(3, result.size());

        CBORValue handover = result.get(2);

        assertNotNull(handover);
        assertTrue(handover.isArray());
        assertEquals(2, handover.size());
        assertArrayEquals(select, handover.get(0).asBytes());
        assertTrue(handover.get(1).isNull());
    }

    @Test
    void securityNotProvided() {
        SessionTranscriptBuilder builder =
                SessionTranscriptBuilder.nfcStaticHandover(new byte[]{0x01});

        Exception exception = assertThrows(NullPointerException.class, builder::buildCbor);
        assertEquals("DeviceEngagement Security Cipher suite identifier is not provided! " +
                "Please use #security method.", exception.getMessage());
    }

    @Test
    void readerKeyMissing() throws Exception {
        PublicKey deviceKey = generateKey();

        SessionTranscriptBuilder builder =
                SessionTranscriptBuilder.nfcStaticHandover(new byte[]{0x01})
                        .security(EllipticCurve.P_256, deviceKey);

        Exception exception = assertThrows(NullPointerException.class, builder::buildCbor);
        assertEquals("eReaderKey is not provided! Please use #eReaderKey method.", exception.getMessage());
    }

    @Test
    void webApiServerRetrievalMethods() throws Exception {
        PublicKey deviceKey = generateKey();
        PublicKey readerKey = generateKey();

        SessionTranscriptBuilder builder =
                SessionTranscriptBuilder.nfcStaticHandover(new byte[]{0x01})
                        .security(EllipticCurve.P_256, deviceKey)
                        .eReaderKey(readerKey)
                        .webApiServerRetrievalMethod(1, "https://issuer", "token");

        CBORValue result = builder.buildCbor();
        assertTrue(result.isArray());
        assertEquals(3, result.size());

        CBORValue deviceEngagementBytes = result.get(0);
        assertTrue(deviceEngagementBytes.isTag());
        assertEquals(24L, deviceEngagementBytes.getTag().longValue());
        assertTrue(deviceEngagementBytes.getTaggedValue().isByteString());

        CBORValue deviceEngagement =
                CBORUtils.parseCbor(deviceEngagementBytes.getTaggedValue().asBytes());

        assertTrue(deviceEngagement.isMap());

        assertEquals("1.0", deviceEngagement.get(0L).asString());

        CBORValue security = deviceEngagement.get(1L);
        assertNotNull(security);
        assertTrue(security.isArray());
        assertEquals(2, security.size());

        assertEquals(
                EllipticCurve.P_256.getCOSEValue(),
                security.get(0).asInteger().longValue());

        CBORValue coseKeyBytes = security.get(1);
        assertTrue(coseKeyBytes.isTag());

        CBORValue coseKeyBytesValue = coseKeyBytes.getTaggedValue();
        assertNotNull(coseKeyBytesValue);
        assertTrue(coseKeyBytesValue.isByteString());

        CBORValue coseKey = CBORUtils.parseCbor(coseKeyBytesValue.asBytes());
        assertTrue(coseKey.isMap());
        assertEquals(4, coseKey.size());

        assertEquals(COSEConstants.COSE_KEY_TYPE_EC2_VALUE,
                coseKey.get(COSEConstants.COSE_KEY_KTY).asInteger().longValue());

        assertEquals(EllipticCurve.P_256.getCOSEValue(),
                coseKey.get(COSEConstants.COSE_KEY_TYPE_EC2_CRV).asInteger().longValue());

        assertEquals(((ECPublicKey) deviceKey).getW().getAffineX(),
                new BigInteger(1, coseKey.get(COSEConstants.COSE_KEY_TYPE_EC2_X).asBytes()));

        assertEquals(((ECPublicKey) deviceKey).getW().getAffineY(),
                new BigInteger(1, coseKey.get(COSEConstants.COSE_KEY_TYPE_EC2_Y).asBytes()));

        assertNull(deviceEngagement.get(2L));

        CBORValue serverRetrievalMethods = deviceEngagement.get(3L);
        assertNotNull(serverRetrievalMethods);
        assertTrue(serverRetrievalMethods.isMap());

        CBORValue webApi = serverRetrievalMethods.get("webApi");
        assertNotNull(webApi);
        assertTrue(webApi.isArray());
        assertEquals(3, webApi.size());

        assertEquals(1, webApi.get(0).asInteger().longValue());
        assertEquals("https://issuer", webApi.get(1).asString());
        assertEquals("token", webApi.get(2).asString());

        assertNotNull(result);
    }

    @Test
    void oidcServerRetrievalMethods() throws Exception {
        PublicKey deviceKey = generateKey();
        PublicKey readerKey = generateKey();

        SessionTranscriptBuilder builder =
                SessionTranscriptBuilder.nfcStaticHandover(new byte[]{0x01})
                        .security(EllipticCurve.P_256, deviceKey)
                        .eReaderKey(readerKey)
                        .oidcServerRetrievalMethod(1, "https://issuer", "token");

        CBORValue result = builder.buildCbor();
        assertTrue(result.isArray());
        assertEquals(3, result.size());

        CBORValue deviceEngagementBytes = result.get(0);
        assertTrue(deviceEngagementBytes.isTag());
        assertEquals(24L, deviceEngagementBytes.getTag().longValue());
        assertTrue(deviceEngagementBytes.getTaggedValue().isByteString());

        CBORValue deviceEngagement =
                CBORUtils.parseCbor(deviceEngagementBytes.getTaggedValue().asBytes());

        assertTrue(deviceEngagement.isMap());

        assertEquals("1.0", deviceEngagement.get(0L).asString());

        CBORValue security = deviceEngagement.get(1L);
        assertNotNull(security);
        assertTrue(security.isArray());
        assertEquals(2, security.size());

        assertEquals(
                EllipticCurve.P_256.getCOSEValue(),
                security.get(0).asInteger().longValue());

        CBORValue coseKeyBytes = security.get(1);
        assertTrue(coseKeyBytes.isTag());

        CBORValue coseKeyBytesValue = coseKeyBytes.getTaggedValue();
        assertNotNull(coseKeyBytesValue);
        assertTrue(coseKeyBytesValue.isByteString());

        CBORValue coseKey = CBORUtils.parseCbor(coseKeyBytesValue.asBytes());
        assertTrue(coseKey.isMap());
        assertEquals(4, coseKey.size());

        assertEquals(COSEConstants.COSE_KEY_TYPE_EC2_VALUE,
                coseKey.get(COSEConstants.COSE_KEY_KTY).asInteger().longValue());

        assertEquals(EllipticCurve.P_256.getCOSEValue(),
                coseKey.get(COSEConstants.COSE_KEY_TYPE_EC2_CRV).asInteger().longValue());

        assertEquals(((ECPublicKey) deviceKey).getW().getAffineX(),
                new BigInteger(1, coseKey.get(COSEConstants.COSE_KEY_TYPE_EC2_X).asBytes()));

        assertEquals(((ECPublicKey) deviceKey).getW().getAffineY(),
                new BigInteger(1, coseKey.get(COSEConstants.COSE_KEY_TYPE_EC2_Y).asBytes()));

        assertNull(deviceEngagement.get(2L));

        CBORValue serverRetrievalMethods = deviceEngagement.get(3L);
        assertNotNull(serverRetrievalMethods);
        assertTrue(serverRetrievalMethods.isMap());

        CBORValue oidc = serverRetrievalMethods.get("oidc");
        assertNotNull(oidc);
        assertTrue(oidc.isArray());
        assertEquals(3, oidc.size());

        assertEquals(1, oidc.get(0).asInteger().longValue());
        assertEquals("https://issuer", oidc.get(1).asString());
        assertEquals("token", oidc.get(2).asString());

        assertNotNull(result);
    }

    @Test
    void reservedDeviceEngagementLabels() throws Exception {
        PublicKey deviceKey = generateKey();

        SessionTranscriptBuilder builder = SessionTranscriptBuilder.nfcStaticHandover(new byte[]{0x01})
                        .security(EllipticCurve.P_256, deviceKey);

        Exception exception = assertThrows(IllegalArgumentException.class,
                () -> builder.otherDeviceEngagementInfo(1, "reserved"));

        assertEquals("The DeviceEngagement label value '1' is reserved!", exception.getMessage());
    }

    @Test
    void qrHandover() throws Exception {
        PublicKey deviceKey = generateKey();
        PublicKey readerKey = generateKey();

        SessionTranscriptBuilder.QRHandoverSessionTranscriptBuilder builder =
                SessionTranscriptBuilder.qrHandover()
                        .security(EllipticCurve.P_256, deviceKey)
                        .eReaderKey(readerKey)
                        .addNfcRetrievalOptions(10, 20);

        CBORValue result = builder.buildCbor();
        assertTrue(result.isArray());
        assertEquals(3, result.size());

        CBORValue deviceEngagementBytes = result.get(0);
        assertTrue(deviceEngagementBytes.isTag());
        assertEquals(24L, deviceEngagementBytes.getTag().longValue());
        assertTrue(deviceEngagementBytes.getTaggedValue().isByteString());

        assertTrue(result.get(1).isTag());
        assertEquals(24L, result.get(1).getTag().longValue());
        assertTrue(result.get(1).getTaggedValue().isByteString());

        // QR handover must be null
        assertTrue(result.get(2).isNull());

        CBORValue deviceEngagementObject =
                CBORUtils.parseCbor(deviceEngagementBytes.getTaggedValue().asBytes());

        assertTrue(deviceEngagementObject.isMap());

        CBORValue methods = deviceEngagementObject.get(2L);
        assertNotNull(methods);
        assertTrue(methods.isArray());
        assertEquals(1, methods.size());

        CBORValue method = methods.get(0);
        assertTrue(method.isArray());

        // Method structure: [type, version, options]
        assertEquals(3, method.size());

        assertEquals(1L, method.get(0).asInteger().longValue());
        assertEquals(1L, method.get(1).asInteger().longValue());

        CBORValue options = method.get(2);
        assertTrue(options.isMap());
        assertEquals(2, options.size());

        assertEquals(10L, options.get(0L).asInteger().longValue());
        assertEquals(20L, options.get(1L).asInteger().longValue());
    }

    @Test
    void qrHandoverMultipleRetrievalMethods() throws Exception {
        PublicKey deviceKey = generateKey();
        PublicKey readerKey = generateKey();

        byte[] wifiBands = new byte[]{0x01, 0x02};
        byte[] bleUuid = new byte[]{0x0A};

        SessionTranscriptBuilder.QRHandoverSessionTranscriptBuilder builder =
                SessionTranscriptBuilder.qrHandover()
                        .security(EllipticCurve.P_256, deviceKey)
                        .eReaderKey(readerKey)
                        .addNfcRetrievalOptions(10, 20)
                        .addWiFiRetrievalOptions("pass", 1, 6, wifiBands)
                        .addBleRetrievalOptions(true, false, bleUuid, bleUuid, bleUuid);

        CBORValue result = builder.buildCbor();
        assertTrue(result.isArray());
        assertEquals(3, result.size());

        CBORValue deviceEngagementBytes = result.get(0);
        assertTrue(deviceEngagementBytes.isTag());
        assertEquals(24L, deviceEngagementBytes.getTag().longValue());
        assertTrue(deviceEngagementBytes.getTaggedValue().isByteString());

        CBORValue deviceEngagementObject =
                CBORUtils.parseCbor(deviceEngagementBytes.getTaggedValue().asBytes());

        assertTrue(deviceEngagementObject.isMap());

        CBORValue methods = deviceEngagementObject.get(2L);
        assertNotNull(methods);
        assertTrue(methods.isArray());
        assertEquals(3, methods.size());

        // ---- NFC ----
        CBORValue nfc = methods.get(0);
        assertTrue(nfc.isArray());
        assertEquals(1L, nfc.get(0).asInteger().longValue());
        assertEquals(1L, nfc.get(1).asInteger().longValue());

        CBORValue nfcOptions = nfc.get(2);
        assertTrue(nfcOptions.isMap());
        assertEquals(10L, nfcOptions.get(0L).asInteger().longValue());
        assertEquals(20L, nfcOptions.get(1L).asInteger().longValue());

        // ---- WiFi ----
        CBORValue wifi = methods.get(1);
        assertTrue(wifi.isArray());
        assertEquals(3L, wifi.get(0).asInteger().longValue());
        assertEquals(1L, wifi.get(1).asInteger().longValue());

        CBORValue wifiOptions = wifi.get(2);
        assertTrue(wifiOptions.isMap());

        assertEquals("pass", wifiOptions.get(0L).asString());
        assertEquals(1L, wifiOptions.get(1L).asInteger().longValue());
        assertEquals(6L, wifiOptions.get(2L).asInteger().longValue());
        assertArrayEquals(wifiBands, wifiOptions.get(3L).asBytes());

        // ---- BLE ----
        CBORValue ble = methods.get(2);
        assertTrue(ble.isArray());
        assertEquals(2L, ble.get(0).asInteger().longValue());
        assertEquals(1L, ble.get(1).asInteger().longValue());

        CBORValue bleOptions = ble.get(2);
        assertTrue(bleOptions.isMap());

        // Only optional fields should be present
        assertEquals(5, bleOptions.size());
        assertTrue(bleOptions.get(0L).asBoolean());
        assertFalse(bleOptions.get(1L).asBoolean());
        assertArrayEquals(bleUuid, bleOptions.get(10L).asBytes());
        assertArrayEquals(bleUuid, bleOptions.get(11L).asBytes());
        assertArrayEquals(bleUuid, bleOptions.get(20L).asBytes());
    }

    @Test
    void qrWithoutRetrievalMethods() throws Exception {
        PublicKey deviceKey = generateKey();
        PublicKey readerKey = generateKey();

        SessionTranscriptBuilder.QRHandoverSessionTranscriptBuilder builder =
                SessionTranscriptBuilder.qrHandover()
                        .security(EllipticCurve.P_256, deviceKey)
                        .eReaderKey(readerKey);

        Exception exception = assertThrows(NullPointerException.class, builder::buildCbor);
        assertEquals("No DeviceRetrievalMethods have been provided! Please add WiFi, BLE or NFC retrieval options!", exception.getMessage());
    }

    @Test
    void protocolInfo() throws Exception {
        PublicKey deviceKey = generateKey();
        PublicKey readerKey = generateKey();

        SessionTranscriptBuilder builder =
                SessionTranscriptBuilder.nfcStaticHandover(new byte[]{0x01})
                        .security(EllipticCurve.P_256, deviceKey)
                        .eReaderKey(readerKey)
                        .protocolInfo("custom");

        CBORValue result = builder.buildCbor();
        assertTrue(result.isArray());
        assertEquals(3, result.size());

        CBORValue deviceEngagementBytes = result.get(0);
        assertTrue(deviceEngagementBytes.isTag());
        assertEquals(24L, deviceEngagementBytes.getTag().longValue());
        assertTrue(deviceEngagementBytes.getTaggedValue().isByteString());

        CBORValue deviceEngagement =
                CBORUtils.parseCbor(deviceEngagementBytes.getTaggedValue().asBytes());

        assertTrue(deviceEngagement.isMap());

        assertEquals("1.0", deviceEngagement.get(0L).asString());

        CBORValue security = deviceEngagement.get(1L);
        assertNotNull(security);
        assertTrue(security.isArray());

        assertNull(deviceEngagement.get(2L));
        assertNull(deviceEngagement.get(3L));

        CBORValue protocolInfo = deviceEngagement.get(4L);
        assertNotNull(protocolInfo);
        assertEquals("custom", protocolInfo.asString());
    }

    @Test
    void otherDeviceEngagementInfo() throws Exception {
        PublicKey deviceKey = generateKey();
        PublicKey readerKey = generateKey();

        SessionTranscriptBuilder builder =
                SessionTranscriptBuilder.nfcStaticHandover(new byte[]{0x01})
                        .security(EllipticCurve.P_256, deviceKey)
                        .eReaderKey(readerKey)
                        .otherDeviceEngagementInfo(10, "customValue");

        CBORValue result = builder.buildCbor();
        assertTrue(result.isArray());

        CBORValue deviceEngagementBytes = result.get(0);
        assertTrue(deviceEngagementBytes.isTag());
        assertEquals(24L, deviceEngagementBytes.getTag().longValue());
        assertTrue(deviceEngagementBytes.getTaggedValue().isByteString());

        CBORValue deviceEngagement =
                CBORUtils.parseCbor(deviceEngagementBytes.getTaggedValue().asBytes());

        assertTrue(deviceEngagement.isMap());

        CBORValue custom = deviceEngagement.get(10L);
        assertNotNull(custom);
        assertEquals("customValue", custom.asString());
    }

    @Test
    void overrideVersion() throws Exception {
        PublicKey deviceKey = generateKey();
        PublicKey readerKey = generateKey();

        SessionTranscriptBuilder builder =
                SessionTranscriptBuilder.nfcStaticHandover(new byte[]{0x01})
                        .version("2.0")
                        .security(EllipticCurve.P_256, deviceKey)
                        .eReaderKey(readerKey);

        CBORValue result = builder.buildCbor();
        assertTrue(result.isArray());

        List<CBORValue> resultList = result.getElements();
        assertEquals(3, resultList.size());

        CBORValue deviceEngagementBytes = resultList.get(0);
        assertTrue(deviceEngagementBytes.isTag());
        assertEquals(24L, deviceEngagementBytes.getTag().longValue());
        assertTrue(deviceEngagementBytes.getTaggedValue().isByteString());

        CBORValue deviceEngagement =
                CBORUtils.parseCbor(deviceEngagementBytes.getTaggedValue().asBytes());

        assertTrue(deviceEngagement.isMap());
        assertEquals("2.0", deviceEngagement.get(0L).asString());
    }

    @Test
    void nfcStaticHandoverSelectMessageWithCorrectErrorMessage() {
        Exception exception = assertThrows(
                NullPointerException.class,
                () -> SessionTranscriptBuilder.nfcStaticHandover(null));

        assertEquals("Handover Select Message cannot be null!", exception.getMessage());
    }

    private PublicKey generateKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        return kp.getPublic();
    }

}
