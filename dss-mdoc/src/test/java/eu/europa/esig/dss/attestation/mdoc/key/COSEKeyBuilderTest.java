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
package eu.europa.esig.dss.attestation.mdoc.key;

import eu.europa.esig.dss.cbades.COSEConstants;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.attestation.common.key.PublicKeyInfo;
import eu.europa.esig.dss.enumerations.EllipticCurve;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class COSEKeyBuilderTest {

    @Test
    void createECKey() {
        byte[] x = { 1, 2, 3 };
        byte[] y = { 4, 5, 6 };

        PublicKeyInfo.ECKey keyInfo = PublicKeyInfo.ecKey(EllipticCurve.P_256, x, y);

        CBORMap cose = new COSEKeyBuilder(keyInfo).create();
        assertEquals(4, cose.getSize());
        assertEquals(COSEConstants.COSE_KEY_TYPE_EC2_VALUE, cose.getAsLong(COSEConstants.COSE_KEY_KTY));
        assertEquals(EllipticCurve.P_256.getCOSEValue(), cose.getAsLong(COSEConstants.COSE_KEY_TYPE_EC2_CRV));
        assertArrayEquals(x, cose.getAsBinaries(COSEConstants.COSE_KEY_TYPE_EC2_X));
        assertArrayEquals(y, cose.getAsBinaries(COSEConstants.COSE_KEY_TYPE_EC2_Y));
    }

    @Test
    void createOKPKey() {
        byte[] x = { 10, 20, 30 };

        PublicKeyInfo.OKPKey keyInfo = PublicKeyInfo.okpKey(EllipticCurve.ED25519, x);

        CBORMap cose = new COSEKeyBuilder(keyInfo).create();
        assertEquals(3, cose.getSize());
        assertEquals(COSEConstants.COSE_KEY_TYPE_OKP_VALUE, cose.getAsLong(COSEConstants.COSE_KEY_KTY));
        assertEquals(EllipticCurve.ED25519.getCOSEValue(), cose.getAsLong(COSEConstants.COSE_KEY_TYPE_OKP_CRV));
        assertArrayEquals(x, cose.getAsBinaries(COSEConstants.COSE_KEY_TYPE_OKP_X));
    }

    @Test
    void createRSAKey() {
        byte[] modulus = { 1, 2, 3, 4 };
        byte[] exponent = { 1, 0, 1 };

        PublicKeyInfo.RSAKey keyInfo = PublicKeyInfo.rsaKey(modulus, exponent);

        CBORMap cose = new COSEKeyBuilder(keyInfo).create();
        assertEquals(3, cose.getSize());
        assertEquals(COSEConstants.COSE_KEY_TYPE_RSA_VALUE, cose.getAsLong(COSEConstants.COSE_KEY_KTY));
        assertArrayEquals(modulus, cose.getAsBinaries(COSEConstants.COSE_KEY_TYPE_RSA_N));
        assertArrayEquals(exponent, cose.getAsBinaries(COSEConstants.COSE_KEY_TYPE_RSA_E));
    }

    @Test
    void createThrowsWhenNull() {
        Exception exception = assertThrows(NullPointerException.class, () -> new COSEKeyBuilder(null));
        assertEquals("Key info cannot be null", exception.getMessage());
    }

    @Test
    void createThrowsForUnsupportedKeyType() {
        PublicKeyInfo unsupported = new PublicKeyInfo() {
            @Override
            public String getKeyType() {
                return "";
            }
        };

        COSEKeyBuilder coseKeyBuilder = new COSEKeyBuilder(unsupported);
        Exception exception = assertThrows(UnsupportedOperationException.class, coseKeyBuilder::create);
        assertEquals("Unsupported key info type: ''", exception.getMessage());
    }

}
