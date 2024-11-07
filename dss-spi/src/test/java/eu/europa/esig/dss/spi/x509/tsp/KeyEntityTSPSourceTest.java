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
package eu.europa.esig.dss.spi.x509.tsp;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyEntityTSPSourceTest {

    private static final File KS_FILE = new File("src/test/resources/self-signed-tsa.p12");
    private static final String KS_TYPE = "PKCS12";
    private static final char[] KS_PASSWORD = "ks-password".toCharArray();
    private static final String ALIAS = "self-signed-tsa";
    private static final String TSA_POLICY = "1.2.3.4";

    private static final byte[] DTBS = "Hello World!".getBytes();

    @Test
    void test() throws Exception {
        KeyEntityTSPSource tspSource = new KeyEntityTSPSource(KS_FILE, KS_TYPE, KS_PASSWORD, ALIAS, KS_PASSWORD);
        tspSource.setTsaPolicy(TSA_POLICY);
        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DTBS);
        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        TimeStampToken timeStampToken = assertTimestampValid(timeStampResponse, digest);

        AttributeTable signedAttributes = timeStampToken.getSignedAttributes();
        Attribute[] signingTimeAttrs = DSSASN1Utils.getAsn1Attributes(signedAttributes, CMSAttributes.signingTime);
        assertEquals(1, Utils.arraySize(signingTimeAttrs));
        final ASN1Set attrValues = signingTimeAttrs[0].getAttrValues();
        final ASN1Encodable attrValue = attrValues.getObjectAt(0);

        assertEquals(0, timeStampToken.getTimeStampInfo().getGenTime().compareTo(DSSASN1Utils.getDate(attrValue)));
    }

    @Test
    void noPolicyTest() throws Exception {
        KeyEntityTSPSource tspSource = new KeyEntityTSPSource(KS_FILE, KS_TYPE, KS_PASSWORD, ALIAS, KS_PASSWORD);
        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DTBS);
        Exception exception = assertThrows(NullPointerException.class, () -> tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest));
        assertEquals("TSAPolicy OID is not defined! Use #setTsaPolicy method.", exception.getMessage());
    }

    @Test
    void initWithKeyStoreTest() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KS_TYPE);
        keyStore.load(Files.newInputStream(KS_FILE.toPath()), KS_PASSWORD);

        KeyEntityTSPSource tspSource = new KeyEntityTSPSource(keyStore, ALIAS, KS_PASSWORD);
        tspSource.setTsaPolicy(TSA_POLICY);

        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DTBS);
        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        assertTimestampValid(timeStampResponse, digest);
    }

    @Test
    void acceptedDigestAlgorithmsTest() throws Exception {
        KeyEntityTSPSource tspSource = new KeyEntityTSPSource(KS_FILE, KS_TYPE, KS_PASSWORD, ALIAS, KS_PASSWORD);
        tspSource.setTsaPolicy(TSA_POLICY);

        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, DTBS);
        Exception exception = assertThrows(DSSException.class, () -> tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest));
        assertEquals("DigestAlgorithm 'SHA1' is not supported by the KeyEntityTSPSource implementation!", exception.getMessage());

        tspSource.setAcceptedDigestAlgorithms(Collections.singletonList(DigestAlgorithm.SHA1));
        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest);
        assertTimestampValid(timeStampResponse, digest);
    }

    @Test
    void tsaPolicyTest() throws Exception {
        KeyEntityTSPSource tspSource = new KeyEntityTSPSource(KS_FILE, KS_TYPE, KS_PASSWORD, ALIAS, KS_PASSWORD);
        tspSource.setTsaPolicy("1.5.6.7.8.9");

        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DTBS);
        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        TimeStampToken timeStampToken = assertTimestampValid(timeStampResponse, digest);
        assertEquals("1.5.6.7.8.9", timeStampToken.getTimeStampInfo().getPolicy().getId());
    }

    @Test
    void productionDateTest() throws Exception {
        KeyEntityTSPSource tspSource = new KeyEntityTSPSource(KS_FILE, KS_TYPE, KS_PASSWORD, ALIAS, KS_PASSWORD);
        tspSource.setTsaPolicy(TSA_POLICY);

        Calendar calendar = Calendar.getInstance();
        calendar.clear();
        calendar.set(2022, Calendar.JANUARY, 1);
        Date time = calendar.getTime();
        tspSource.setProductionTime(time);

        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DTBS);
        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        TimeStampToken timeStampToken = assertTimestampValid(timeStampResponse, digest);
        assertEquals(0, time.compareTo(timeStampToken.getTimeStampInfo().getGenTime()));

        AttributeTable signedAttributes = timeStampToken.getSignedAttributes();
        Attribute[] signingTimeAttrs = DSSASN1Utils.getAsn1Attributes(signedAttributes, CMSAttributes.signingTime);
        assertEquals(1, Utils.arraySize(signingTimeAttrs));
        final ASN1Set attrValues = signingTimeAttrs[0].getAttrValues();
        final ASN1Encodable attrValue = attrValues.getObjectAt(0);
        assertEquals(0, time.compareTo(DSSASN1Utils.getDate(attrValue)));
    }

    @Test
    void serialNumberTest() throws Exception {
        KeyEntityTSPSource tspSource = new KeyEntityTSPSource(KS_FILE, KS_TYPE, KS_PASSWORD, ALIAS, KS_PASSWORD);
        tspSource.setTsaPolicy(TSA_POLICY);
        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DTBS);
        TimestampBinary timeStampResponseOne = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        TimeStampToken timeStampTokenOne = assertTimestampValid(timeStampResponseOne, digest);
        TimestampBinary timeStampResponseTwo = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        TimeStampToken timeStampTokenTwo = assertTimestampValid(timeStampResponseTwo, digest);
        assertNotEquals(timeStampTokenOne.getTimeStampInfo().getSerialNumber(), timeStampTokenTwo.getTimeStampInfo().getSerialNumber());
    }

    @Test
    void digestAlgoTest() throws Exception {
        KeyEntityTSPSource tspSource = new KeyEntityTSPSource(KS_FILE, KS_TYPE, KS_PASSWORD, ALIAS, KS_PASSWORD);
        tspSource.setDigestAlgorithm(DigestAlgorithm.SHA256);
        tspSource.setTsaPolicy(TSA_POLICY);

        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DTBS);
        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        TimeStampToken timeStampToken = assertTimestampValid(timeStampResponse, digest);
        assertEquals(SignatureAlgorithm.RSA_SHA256.getOid(), timeStampToken.toCMSSignedData().getSignerInfos().get(timeStampToken.getSID()).getEncryptionAlgOID());

        tspSource.setDigestAlgorithm(DigestAlgorithm.SHA512);

        timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        timeStampToken = assertTimestampValid(timeStampResponse, digest);
        assertEquals(SignatureAlgorithm.RSA_SHA512.getOid(), timeStampToken.toCMSSignedData().getSignerInfos().get(timeStampToken.getSID()).getEncryptionAlgOID());
    }

    @Test
    void pssTest() throws Exception {
        KeyEntityTSPSource tspSource = new KeyEntityTSPSource(KS_FILE, KS_TYPE, KS_PASSWORD, ALIAS, KS_PASSWORD);
        tspSource.setDigestAlgorithm(DigestAlgorithm.SHA256);
        tspSource.setTsaPolicy(TSA_POLICY);
        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DTBS);
        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        TimeStampToken timeStampToken = assertTimestampValid(timeStampResponse, digest);
        assertEquals(SignatureAlgorithm.RSA_SHA256.getOid(), timeStampToken.toCMSSignedData().getSignerInfos().get(timeStampToken.getSID()).getEncryptionAlgOID());

        tspSource.setEncryptionAlgorithm(EncryptionAlgorithm.RSASSA_PSS);

        timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        timeStampToken = assertTimestampValid(timeStampResponse, digest);
        // the same OID is used for RSAwithANYandMGF1
        assertEquals(SignatureAlgorithm.RSA_SSA_PSS_SHA1_MGF1.getOid(), timeStampToken.toCMSSignedData().getSignerInfos().get(timeStampToken.getSID()).getEncryptionAlgOID());
    }

    @Test
    void errorTest() throws Exception {
        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DTBS);

        Exception exception1 = assertThrows(NullPointerException.class, () ->new KeyEntityTSPSource((KeyStore) null, null, null));
        assertEquals("KeyStore is not defined!", exception1.getMessage());

        KeyStore keyStore = KeyStore.getInstance(KS_TYPE);
        try (InputStream is = Files.newInputStream(KS_FILE.toPath())) {
            keyStore.load(is, KS_PASSWORD);
        }

        Exception exception = assertThrows(NullPointerException.class, () -> new KeyEntityTSPSource(keyStore, null, null));
        assertEquals("Alias is not defined!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> new KeyEntityTSPSource(keyStore, ALIAS, null));
        assertEquals("KeyEntry Password is not defined!", exception.getMessage());

        KeyEntityTSPSource tspSource = new KeyEntityTSPSource(keyStore, ALIAS, KS_PASSWORD);
        tspSource.setTsaPolicy(TSA_POLICY);
        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        assertTimestampValid(timeStampResponse, digest);

        exception = assertThrows(IllegalArgumentException.class, () -> new KeyEntityTSPSource(keyStore, "wrong-alias", KS_PASSWORD));
        assertEquals("No related/supported key entry found for alias 'wrong-alias'!", exception.getMessage());

        exception = assertThrows(DSSException.class, () -> new KeyEntityTSPSource(keyStore, ALIAS, "wrong-password".toCharArray()));
        assertTrue(exception.getMessage().contains("Unable to recover the key entry with alias 'self-signed-tsa'."));
    }

    private TimeStampToken assertTimestampValid(TimestampBinary timestampBinary, byte[] digest) throws Exception {
        assertNotNull(timestampBinary);
        assertNotNull(timestampBinary.getBytes());
        assertFalse(Arrays.equals(new byte[] {}, timestampBinary.getBytes()));

        CMSSignedData cmsSignedData = new CMSSignedData(timestampBinary.getBytes());
        TimeStampToken timeStampToken = new TimeStampToken(cmsSignedData);
        assertArrayEquals(digest, timeStampToken.getTimeStampInfo().getMessageImprintDigest());
        return timeStampToken;
    }
    
}
