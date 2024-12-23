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
package eu.europa.esig.dss.token.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.DSSUtils;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class DigestInfoEncoderTest {

    @Test
    void testEncodeValid() {
        byte[] digest = Base64.decode("dyizBEA7ZIGgNmI+fO3Y9zUyMo4ClqzY6caszQgWs0U=");
        byte[] result = DigestInfoEncoder.encode(DigestAlgorithm.SHA256.getOid(), digest);
        byte[] expected = Base64.decode("MDEwDQYJYIZIAWUDBAIBBQAEIHcoswRAO2SBoDZiPnzt2Pc1MjKOApas2OnGrM0IFrNF");
        assertArrayEquals(expected, result);
    }

    @Test
    void testEncodeEmptyDigest() {
        byte[] digest = new byte[0];
        byte[] result = DigestInfoEncoder.encode(DigestAlgorithm.SHA256.getOid(), digest);
        byte[] expected = Base64.decode("MBEwDQYJYIZIAWUDBAIBBQAEAA==");
        assertArrayEquals(expected, result);
    }

    @Test
    void testEncodeInvalidDigestAlgorithm() {
        byte[] digest = new byte[0];
        Exception exception = assertThrows(DSSException.class, () -> DigestInfoEncoder.encode("", digest));
        assertEquals("An error occurred on DigestInfo encoding : For input string: \"\"", exception.getMessage());
    }

    @Test
    void testEncodeDigestAlgorithmNull() {
        byte[] digest = new byte[0];
        Exception exception = assertThrows(NullPointerException.class, () -> DigestInfoEncoder.encode(null, digest));
        assertEquals("Digest algorithm OID cannot be null!", exception.getMessage());
    }

    @Test
    void testEncodeDigestNull() {
        Exception exception = assertThrows(NullPointerException.class, () -> DigestInfoEncoder.encode(DigestAlgorithm.SHA256.getOid(), null));
        assertEquals("Digest cannot be null!", exception.getMessage());
    }

    @Test
    void testIsEncodedValid() {
        byte[] data = Base64.decode("MDEwDQYJYIZIAWUDBAIBBQAEIHcoswRAO2SBoDZiPnzt2Pc1MjKOApas2OnGrM0IFrNF");
        assertTrue(DigestInfoEncoder.isEncoded(data));
    }

    @Test
    void testIsEncodedTruncatedData() {
        byte[] data = Base64.decode("MDEwDQYJYIZIAWUDBAIBBQAEIHcoswRAO2SBoDZiPnzt2Pc1MjKOApas2OnGrM0IFrNF");
        assertTrue(DigestInfoEncoder.isEncoded(data));

        // Loop to remove one byte at a time from the end of the array
        for (int i = data.length - 1; i > 0; i--) {
            byte[] truncatedData = new byte[i];
            System.arraycopy(data, 0, truncatedData, 0, i);
            assertFalse(DigestInfoEncoder.isEncoded(truncatedData));
        }
    }

    @Test
    void testIsEncodedInvalidTag() {
        byte[] data = Base64.decode("MUIwDQYJKoZIhvcNAQEFBQADHgA7RjpypAxTb+WRBA9gQwPZcMclDmpHPXG97Yj8");
        assertFalse(DigestInfoEncoder.isEncoded(data));
    }

    @Test
    void testIsEncodedInvalidStructure() {
        byte[] data = Base64.decode("AAA=");
        assertFalse(DigestInfoEncoder.isEncoded(data));
    }

    @Test
    void testIsEncodedEmpty() {
        assertFalse(DigestInfoEncoder.isEncoded(new byte[0]));
    }

    @Test
    void testIsEncodedNull() {
        assertFalse(DigestInfoEncoder.isEncoded(null));
    }

    @Test
    void crossVerificationWithBouncyCastleTest() {
        Security.addProvider(DSSSecurityProvider.getSecurityProvider());

        byte[] data = "Hello world!".getBytes(StandardCharsets.UTF_8);

        for (DigestAlgorithm digestAlgorithm : DigestAlgorithm.values()) {
            String oid = digestAlgorithm.getOid();

            byte[] digest = DSSUtils.digest(digestAlgorithm, data);
            assertFalse(isEncodedBC(digest));
            assertFalse(DigestInfoEncoder.isEncoded(digest));
            byte[] digestInfoBC = bcEncode(oid, digest);
            assertTrue(isEncodedBC(digestInfoBC));
            assertTrue(DigestInfoEncoder.isEncoded(digestInfoBC));

            digest = DSSUtils.digest(digestAlgorithm, data);
            assertFalse(isEncodedBC(digest));
            assertFalse(DigestInfoEncoder.isEncoded(digest));
            byte[] digestInfoLocal = DigestInfoEncoder.encode(oid, digest);
            assertTrue(isEncodedBC(digestInfoLocal));
            assertTrue(DigestInfoEncoder.isEncoded(digestInfoLocal));

            assertArrayEquals(digestInfoBC, digestInfoLocal);
        }

    }

    private byte[] bcEncode(String oid, byte[] digest) {
        try {
            AlgorithmIdentifier algId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid), DERNull.INSTANCE);
            DigestInfo digestInfo = new DigestInfo(algId, digest);
            return digestInfo.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            fail("Unable to encode digest", e);
            return null;
        }
    }
    
    private boolean isEncodedBC(byte[] bytes) {
        try {
            return DigestInfo.getInstance(bytes) != null;
        } catch (Exception e) {
            return false;
        }
    }

}
