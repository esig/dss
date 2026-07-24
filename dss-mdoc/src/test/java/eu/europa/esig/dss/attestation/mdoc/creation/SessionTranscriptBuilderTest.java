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

import eu.europa.esig.dss.cbades.COSEConstants;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORNull;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORSimpleObject;
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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
        CBORObject cborObject = builder.buildCbor();
        assertArrayEquals(DSSUtils.toByteArray(document), CBORUtils.serializeCborObject(cborObject));

        SessionTranscriptBuilder builder2 =
                SessionTranscriptBuilder.nfcHandover(select, request)
                        .security(EllipticCurve.P_256, deviceKey)
                        .eReaderKey(readerKey);

        DSSDocument document2 = builder2.build();
        CBORObject cborObject2 = builder2.buildCbor();
        assertArrayEquals(DSSUtils.toByteArray(document), CBORUtils.serializeCborObject(cborObject));
        assertArrayEquals(DSSUtils.toByteArray(document), DSSUtils.toByteArray(document2));
        assertArrayEquals(CBORUtils.serializeCborObject(cborObject), CBORUtils.serializeCborObject(cborObject2));
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

        CBORArray result = (CBORArray) builder.buildCbor();
        List<CBORObject> resultList = result.getValueAsList();
        assertEquals(3, resultList.size());

        CBORByteString deviceEngagementBytes = assertInstanceOf(CBORByteString.class, resultList.get(0));
        assertEquals(24L, deviceEngagementBytes.getTag().getValue());

        CBORByteString readerKeyBytes = assertInstanceOf(CBORByteString.class, resultList.get(1));
        assertEquals(24L, readerKeyBytes.getTag().getValue());

        CBORMap readerKeyCbor = (CBORMap) CBORUtils.parseCbor(readerKeyBytes.getValueAsBytes());

        assertEquals(COSEConstants.COSE_KEY_TYPE_EC2_VALUE,
                readerKeyCbor.getAsLong(COSEConstants.COSE_KEY_KTY));

        assertEquals(EllipticCurve.P_256.getCOSEValue(),
                readerKeyCbor.getAsLong(COSEConstants.COSE_KEY_TYPE_EC2_CRV));

        CBORObject handover = resultList.get(2);
        CBORArray handoverArray = assertInstanceOf(CBORArray.class, handover);

        assertNotNull(handoverArray);
        assertArrayEquals(select, handoverArray.getAsBinaries(0));
        assertArrayEquals(request, handoverArray.getAsBinaries(1));
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

        CBORArray result = (CBORArray) builder.buildCbor();

        CBORArray handover = result.getAsArray(2);

        assertNotNull(handover);
        assertNotNull(handover.getAsBinaries(0));
        assertNull(handover.getAsBinaries(1));
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

        CBORArray result = (CBORArray) builder.buildCbor();
        List<CBORObject> resultList = result.getValueAsList();
        assertEquals(3, resultList.size());

        CBORByteString deviceEngagementBytes = assertInstanceOf(CBORByteString.class, resultList.get(0));
        assertNotNull(deviceEngagementBytes.getTag());
        assertEquals(24L, deviceEngagementBytes.getTag().getValue());

        CBORObject deviceEngagement = CBORUtils.parseCbor(deviceEngagementBytes.getValueAsBytes());
        CBORMap deviceEngagementMap = assertInstanceOf(CBORMap.class, deviceEngagement);

        assertEquals("1.0", deviceEngagementMap.getAsString(0L));

        CBORArray security = deviceEngagementMap.getAsArray(1L);
        assertNotNull(security);
        List<CBORObject> securityList = security.getValueAsList();

        CBORSimpleObject cipherSuiteIdentifier = assertInstanceOf(CBORSimpleObject.class, securityList.get(0));
        assertEquals(EllipticCurve.P_256.getCOSEValue(), cipherSuiteIdentifier.getValueAsLong());

        CBORByteString coseKeyBytes = assertInstanceOf(CBORByteString.class, securityList.get(1));
        CBORObject coseKeyObject = CBORUtils.parseCbor(coseKeyBytes.getValueAsBytes());

        CBORMap coseKey = assertInstanceOf(CBORMap.class, coseKeyObject);
        assertEquals(4, coseKey.getSize());
        assertEquals(COSEConstants.COSE_KEY_TYPE_EC2_VALUE, coseKey.getAsLong(COSEConstants.COSE_KEY_KTY));
        assertEquals(EllipticCurve.P_256.getCOSEValue(), coseKey.getAsLong(COSEConstants.COSE_KEY_TYPE_EC2_CRV));
        assertEquals(((ECPublicKey) deviceKey).getW().getAffineX(), new BigInteger(1, coseKey.getAsBinaries(COSEConstants.COSE_KEY_TYPE_EC2_X)));
        assertEquals(((ECPublicKey) deviceKey).getW().getAffineY(), new BigInteger(1, coseKey.getAsBinaries(COSEConstants.COSE_KEY_TYPE_EC2_Y)));

        CBORArray deviceRetrievalMethods = deviceEngagementMap.getAsArray(2L);
        assertNull(deviceRetrievalMethods);

        CBORMap serverRetrievalMethods = deviceEngagementMap.getAsMap(3L);
        assertNotNull(serverRetrievalMethods);

        CBORArray webApi = serverRetrievalMethods.getAsArray("webApi");
        assertNotNull(webApi);
        assertEquals(1, webApi.getAsLong(0));
        assertEquals("https://issuer", webApi.getAsString(1));
        assertEquals("token", webApi.getAsString(2));

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

        CBORArray result = (CBORArray) builder.buildCbor();
        List<CBORObject> resultList = result.getValueAsList();
        assertEquals(3, resultList.size());

        CBORByteString deviceEngagementBytes = assertInstanceOf(CBORByteString.class, resultList.get(0));
        assertNotNull(deviceEngagementBytes.getTag());
        assertEquals(24L, deviceEngagementBytes.getTag().getValue());

        CBORObject deviceEngagement = CBORUtils.parseCbor(deviceEngagementBytes.getValueAsBytes());
        CBORMap deviceEngagementMap = assertInstanceOf(CBORMap.class, deviceEngagement);

        assertEquals("1.0", deviceEngagementMap.getAsString(0L));

        CBORArray security = deviceEngagementMap.getAsArray(1L);
        assertNotNull(security);
        List<CBORObject> securityList = security.getValueAsList();

        CBORSimpleObject cipherSuiteIdentifier = assertInstanceOf(CBORSimpleObject.class, securityList.get(0));
        assertEquals(EllipticCurve.P_256.getCOSEValue(), cipherSuiteIdentifier.getValueAsLong());

        CBORByteString coseKeyBytes = assertInstanceOf(CBORByteString.class, securityList.get(1));
        CBORObject coseKeyObject = CBORUtils.parseCbor(coseKeyBytes.getValueAsBytes());

        CBORMap coseKey = assertInstanceOf(CBORMap.class, coseKeyObject);
        assertEquals(4, coseKey.getSize());
        assertEquals(COSEConstants.COSE_KEY_TYPE_EC2_VALUE, coseKey.getAsLong(COSEConstants.COSE_KEY_KTY));
        assertEquals(EllipticCurve.P_256.getCOSEValue(), coseKey.getAsLong(COSEConstants.COSE_KEY_TYPE_EC2_CRV));
        assertEquals(((ECPublicKey) deviceKey).getW().getAffineX(), new BigInteger(1, coseKey.getAsBinaries(COSEConstants.COSE_KEY_TYPE_EC2_X)));
        assertEquals(((ECPublicKey) deviceKey).getW().getAffineY(), new BigInteger(1, coseKey.getAsBinaries(COSEConstants.COSE_KEY_TYPE_EC2_Y)));

        CBORArray deviceRetrievalMethods = deviceEngagementMap.getAsArray(2L);
        assertNull(deviceRetrievalMethods);

        CBORMap serverRetrievalMethods = deviceEngagementMap.getAsMap(3L);
        assertNotNull(serverRetrievalMethods);

        CBORArray webApi = serverRetrievalMethods.getAsArray("oidc");
        assertNotNull(webApi);
        assertEquals(1, webApi.getAsLong(0));
        assertEquals("https://issuer", webApi.getAsString(1));
        assertEquals("token", webApi.getAsString(2));

        assertNotNull(result);
    }

    @Test
    void reservedDeviceEngagementLabels() throws Exception {
        PublicKey deviceKey = generateKey();

        SessionTranscriptBuilder builder =
                SessionTranscriptBuilder.nfcStaticHandover(new byte[]{0x01})
                        .security(EllipticCurve.P_256, deviceKey);

        Exception exception = assertThrows(IllegalArgumentException.class, () -> builder.otherDeviceEngagementInfo(1, "reserved"));
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

        CBORArray result = (CBORArray) builder.buildCbor();
        assertEquals(3, result.getSize());

        List<CBORObject> resultList = result.getValueAsList();
        assertInstanceOf(CBORByteString.class, resultList.get(0));
        assertInstanceOf(CBORByteString.class, resultList.get(1));
        // QR handover must be null
        assertInstanceOf(CBORNull.class, resultList.get(2));

        CBORByteString deviceEngagementBytes = assertInstanceOf(CBORByteString.class, resultList.get(0));
        CBORObject deviceEngagementObject = CBORUtils.parseCbor(deviceEngagementBytes.getValueAsBytes());
        CBORMap deviceEngagement = assertInstanceOf(CBORMap.class, deviceEngagementObject);

        CBORArray methods = deviceEngagement.getAsArray(2L);
        assertNotNull(methods);
        assertEquals(1, methods.getSize());

        CBORArray method = methods.getAsArray(0);

        // Method structure: [type, version, options]
        assertEquals(3, method.getSize());

        assertEquals(1L, method.getAsLong(0));

        assertEquals(1L, method.getAsLong(1));

        CBORMap options = method.getAsMap(2);
        assertEquals(2, options.getSize());
        assertEquals(10L, options.getAsLong(0));
        assertEquals(20L, options.getAsLong(1));
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

        CBORArray result = (CBORArray) builder.buildCbor();
        assertEquals(3, result.getSize());

        List<CBORObject> resultList = result.getValueAsList();

        CBORByteString deviceEngagementBytes = assertInstanceOf(CBORByteString.class, resultList.get(0));
        CBORObject deviceEngagementObject = CBORUtils.parseCbor(deviceEngagementBytes.getValueAsBytes());
        CBORMap deviceEngagement = assertInstanceOf(CBORMap.class, deviceEngagementObject);

        CBORArray methods = deviceEngagement.getAsArray(2L);

        assertNotNull(methods);
        assertEquals(3, methods.getSize());

        // ---- NFC ----
        CBORArray nfc = methods.getAsArray(0);
        assertEquals(1L, nfc.getAsLong(0));
        assertEquals(1L, nfc.getAsLong(1));

        CBORMap nfcOptions = nfc.getAsMap(2);
        assertEquals(10L, nfcOptions.getAsLong(0));
        assertEquals(20L, nfcOptions.getAsLong(1));

        // ---- WiFi ----
        CBORArray wifi = methods.getAsArray(1);
        assertEquals(3L, wifi.getAsLong(0)); // WiFi type
        assertEquals(1L, wifi.getAsLong(1));

        CBORMap wifiOptions = wifi.getAsMap(2);
        assertEquals("pass", wifiOptions.getAsString(0));
        assertEquals(1L, wifiOptions.getAsLong(1));
        assertEquals(6L, wifiOptions.getAsLong(2));
        assertArrayEquals(wifiBands, wifiOptions.getAsBinaries(3));

        // ---- BLE ----
        CBORArray ble = methods.getAsArray(2);
        assertEquals(2L, ble.getAsLong(0)); // BLE type
        assertEquals(1L, ble.getAsLong(1));

        CBORMap bleOptions = ble.getAsMap(2);

        // Only optional fields should be present
        assertEquals(5, bleOptions.getSize());
        assertEquals(true, bleOptions.getAsBoolean(0));
        assertEquals(false, bleOptions.getAsBoolean(1));
        assertArrayEquals(bleUuid, bleOptions.getAsBinaries(10));
        assertArrayEquals(bleUuid, bleOptions.getAsBinaries(11));
        assertArrayEquals(bleUuid, bleOptions.getAsBinaries(20));
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


        CBORArray result = (CBORArray) builder.buildCbor();
        List<CBORObject> resultList = result.getValueAsList();
        assertEquals(3, resultList.size());

        CBORByteString deviceEngagementBytes = assertInstanceOf(CBORByteString.class, resultList.get(0));
        assertNotNull(deviceEngagementBytes.getTag());
        assertEquals(24L, deviceEngagementBytes.getTag().getValue());

        CBORObject deviceEngagement = CBORUtils.parseCbor(deviceEngagementBytes.getValueAsBytes());
        CBORMap deviceEngagementMap = assertInstanceOf(CBORMap.class, deviceEngagement);

        assertEquals("1.0", deviceEngagementMap.getAsString(0L));

        CBORArray security = deviceEngagementMap.getAsArray(1L);
        assertNotNull(security);

        CBORArray deviceRetrievalMethods = deviceEngagementMap.getAsArray(2L);
        assertNull(deviceRetrievalMethods);

        CBORMap serverRetrievalMethods = deviceEngagementMap.getAsMap(3L);
        assertNull(serverRetrievalMethods);

        CBORObject protocolInfo = deviceEngagementMap.getHeader(4L);
        assertNotNull(protocolInfo);
        CBORSimpleObject protocolInfoSimple = assertInstanceOf(CBORSimpleObject.class, protocolInfo);
        assertEquals("custom", protocolInfoSimple.getValueAsString());
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

        CBORArray result = (CBORArray) builder.buildCbor();
        List<CBORObject> resultList = result.getValueAsList();

        CBORByteString deviceEngagementBytes = (CBORByteString) resultList.get(0);
        CBORMap deviceEngagement =
                (CBORMap) CBORUtils.parseCbor(deviceEngagementBytes.getValueAsBytes());

        CBORObject custom = deviceEngagement.getHeader(10L);
        assertNotNull(custom);

        CBORSimpleObject simple = assertInstanceOf(CBORSimpleObject.class, custom);
        assertEquals("customValue", simple.getValueAsString());
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

        CBORObject result = builder.buildCbor();
        List<CBORObject> resultList = result.getValueAsList();
        assertEquals(3, resultList.size());

        CBORByteString deviceEngagementBytes = assertInstanceOf(CBORByteString.class, resultList.get(0));
        assertNotNull(deviceEngagementBytes.getTag());
        assertEquals(24L, deviceEngagementBytes.getTag().getValue());

        CBORObject deviceEngagement = CBORUtils.parseCbor(deviceEngagementBytes.getValueAsBytes());
        CBORMap deviceEngagementMap = assertInstanceOf(CBORMap.class, deviceEngagement);

        assertEquals("2.0", deviceEngagementMap.getAsString(0L));
    }

    @Test
    void nfcStaticHandoverSelectMessageWithCorrectErrorMessage() {
        Exception exception = assertThrows(NullPointerException.class,
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
