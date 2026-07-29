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
package eu.europa.esig.dss.attestation.common.key;

import eu.europa.esig.dss.enumerations.EllipticCurve;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultPublicKeyInfoFactoryTest {

    private static PublicKeyInfoFactory factory;

    @BeforeAll
    static void setup() {
        factory = new DefaultPublicKeyInfoFactory();
    }

    @Test
    void testECDSA_P256() throws Exception {
        KeyPair kp = generateEC("secp256r1");
        PublicKeyInfo publicKeyInfo = factory.create(kp.getPublic());

        PublicKeyInfo.ECKey ecKey = assertInstanceOf(PublicKeyInfo.ECKey.class, publicKeyInfo);
        assertEquals(EllipticCurve.P_256, ecKey.getCurve());
        assertEquals(EllipticCurve.P_256.getSize(), ecKey.getX().length);
        assertEquals(EllipticCurve.P_256.getSize(), ecKey.getY().length);
    }

    @Test
    void testECDSA_P384() throws Exception {
        KeyPair kp = generateEC("secp384r1");
        PublicKeyInfo publicKeyInfo = factory.create(kp.getPublic());

        PublicKeyInfo.ECKey ecKey = assertInstanceOf(PublicKeyInfo.ECKey.class, publicKeyInfo);
        assertEquals(EllipticCurve.P_384, ecKey.getCurve());
        assertEquals(EllipticCurve.P_384.getSize(), ecKey.getX().length);
        assertEquals(EllipticCurve.P_384.getSize(), ecKey.getY().length);
    }

    @Test
    void testECDSA_P512() throws Exception {
        KeyPair kp = generateEC("secp521r1");
        PublicKeyInfo publicKeyInfo = factory.create(kp.getPublic());

        PublicKeyInfo.ECKey ecKey = assertInstanceOf(PublicKeyInfo.ECKey.class, publicKeyInfo);
        assertEquals(EllipticCurve.P_521, ecKey.getCurve());
        assertEquals(EllipticCurve.P_521.getSize(), ecKey.getX().length);
        assertEquals(EllipticCurve.P_521.getSize(), ecKey.getY().length);
    }

    @Test
    void testECDSA_brainpoolP256() throws Exception {
        KeyPair kp = generateEC("brainpoolP256r1");
        PublicKeyInfo publicKeyInfo = factory.create(kp.getPublic());

        PublicKeyInfo.ECKey ecKey = assertInstanceOf(PublicKeyInfo.ECKey.class, publicKeyInfo);
        assertEquals(EllipticCurve.BRAINPOOL_P256_R1, ecKey.getCurve());
        assertEquals(EllipticCurve.BRAINPOOL_P256_R1.getSize(), ecKey.getX().length);
        assertEquals(EllipticCurve.BRAINPOOL_P256_R1.getSize(), ecKey.getY().length);
    }

    @Test
    void testECDSA_brainpoolP320() throws Exception {
        KeyPair kp = generateEC("brainpoolP320r1");
        PublicKeyInfo publicKeyInfo = factory.create(kp.getPublic());

        PublicKeyInfo.ECKey ecKey = assertInstanceOf(PublicKeyInfo.ECKey.class, publicKeyInfo);
        assertEquals(EllipticCurve.BRAINPOOL_P320_R1, ecKey.getCurve());
        assertEquals(EllipticCurve.BRAINPOOL_P320_R1.getSize(), ecKey.getX().length);
        assertEquals(EllipticCurve.BRAINPOOL_P320_R1.getSize(), ecKey.getY().length);
    }

    @Test
    void testECDSA_brainpoolP384() throws Exception {
        KeyPair kp = generateEC("brainpoolP384r1");
        PublicKeyInfo publicKeyInfo = factory.create(kp.getPublic());

        PublicKeyInfo.ECKey ecKey = assertInstanceOf(PublicKeyInfo.ECKey.class, publicKeyInfo);
        assertEquals(EllipticCurve.BRAINPOOL_P384_R1, ecKey.getCurve());
        assertEquals(EllipticCurve.BRAINPOOL_P384_R1.getSize(), ecKey.getX().length);
        assertEquals(EllipticCurve.BRAINPOOL_P384_R1.getSize(), ecKey.getY().length);
    }

    @Test
    void testECDSA_brainpoolP512() throws Exception {
        KeyPair kp = generateEC("brainpoolP512r1");
        PublicKeyInfo publicKeyInfo = factory.create(kp.getPublic());

        PublicKeyInfo.ECKey ecKey = assertInstanceOf(PublicKeyInfo.ECKey.class, publicKeyInfo);
        assertEquals(EllipticCurve.BRAINPOOL_P512_R1, ecKey.getCurve());
        assertEquals(EllipticCurve.BRAINPOOL_P512_R1.getSize(), ecKey.getX().length);
        assertEquals(EllipticCurve.BRAINPOOL_P512_R1.getSize(), ecKey.getY().length);
    }

    @Test
    void testEd25519() throws Exception {
        KeyPair kp = generateEd("Ed25519");
        PublicKeyInfo publicKeyInfo = factory.create(kp.getPublic());

        PublicKeyInfo.OKPKey okpKey = assertInstanceOf(PublicKeyInfo.OKPKey.class, publicKeyInfo);
        assertEquals(EllipticCurve.ED25519, okpKey.getCurve());
        assertEquals(EllipticCurve.ED25519.getSize(), okpKey.getX().length);
    }

    @Test
    void testEd448() throws Exception {
        KeyPair kp = generateEd("Ed448");
        PublicKeyInfo publicKeyInfo = factory.create(kp.getPublic());

        PublicKeyInfo.OKPKey okpKey = assertInstanceOf(PublicKeyInfo.OKPKey.class, publicKeyInfo);
        assertEquals(EllipticCurve.ED448, okpKey.getCurve());
        assertEquals(EllipticCurve.ED448.getSize(), okpKey.getX().length);
    }

    @Test
    void testX25519() throws Exception {
        KeyPair kp = generateEd("X25519");
        PublicKeyInfo publicKeyInfo = factory.create(kp.getPublic());

        PublicKeyInfo.OKPKey okpKey = assertInstanceOf(PublicKeyInfo.OKPKey.class, publicKeyInfo);
        assertEquals(EllipticCurve.X25519, okpKey.getCurve());
        assertEquals(EllipticCurve.X25519.getSize(), okpKey.getX().length);
    }

    @Test
    void testX448() throws Exception {
        KeyPair kp = generateEd("X448");
        PublicKeyInfo publicKeyInfo = factory.create(kp.getPublic());

        PublicKeyInfo.OKPKey okpKey = assertInstanceOf(PublicKeyInfo.OKPKey.class, publicKeyInfo);
        assertEquals(EllipticCurve.X448, okpKey.getCurve());
        assertEquals(EllipticCurve.X448.getSize(), okpKey.getX().length);
    }

    @Test
    void testRSA2048() throws Exception {
        KeyPair kp = generateRSA(2048);
        PublicKeyInfo publicKeyInfo = factory.create(kp.getPublic());

        PublicKeyInfo.RSAKey rsaKey = assertInstanceOf(PublicKeyInfo.RSAKey.class, publicKeyInfo);
        assertEquals(256, rsaKey.getModulus().length); // 2048 bits
        assertTrue(rsaKey.getExponent().length <= 4); // usually 3 bytes (65537)
    }

    @Test
    void testRSA4096() throws Exception {
        KeyPair kp = generateRSA(4096);

        PublicKeyInfo publicKeyInfo = factory.create(kp.getPublic());

        PublicKeyInfo.RSAKey rsaKey = assertInstanceOf(PublicKeyInfo.RSAKey.class, publicKeyInfo);
        assertEquals(512, rsaKey.getModulus().length);
        assertTrue(rsaKey.getExponent().length <= 4); // usually 3 bytes (65537)
    }

    @Test
    void testNull() {
        Exception exception = assertThrows(NullPointerException.class, () -> factory.create(null));
        assertEquals("Public key cannot be null!", exception.getMessage());
    }

    @Test
    void testUnsupportedKey() {
        PublicKey fakeKey = new PublicKey() {

            private static final long serialVersionUID = 2417707349262582123L;

            public String getAlgorithm() { return "Fake"; }
            public String getFormat() { return "X.509"; }
            public byte[] getEncoded() { return new byte[0]; }
        };

        Exception exception = assertThrows(UnsupportedOperationException.class, () -> factory.create(fakeKey));
        assertEquals("The key of type '' is not supported! Provide a custom PublicKeyInfoFactory should you need to support the key.", exception.getMessage());
    }

    private KeyPair generateEC(String curve) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    private KeyPair generateEd(String alg) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, "BC");
        return kpg.generateKeyPair();
    }

    private KeyPair generateRSA(int size) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(size);
        return kpg.generateKeyPair();
    }

}
