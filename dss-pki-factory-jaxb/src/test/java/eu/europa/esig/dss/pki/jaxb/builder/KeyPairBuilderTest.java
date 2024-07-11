/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pki.jaxb.builder;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyPairBuilderTest {

    @Test
    void rsa1024(){
        KeyPairBuilder builder = new KeyPairBuilder(EncryptionAlgorithm.RSA, 1024);
        KeyPair kp = builder.build();
        assertNotNull(kp);

        assertEquals(EncryptionAlgorithm.RSA.getName(), kp.getPrivate().getAlgorithm());
        assertTrue(kp.getPrivate() instanceof RSAPrivateKey);
        assertEquals(1024, ((RSAPrivateKey) kp.getPrivate()).getModulus().bitLength());

        assertEquals(EncryptionAlgorithm.RSA.getName(), kp.getPublic().getAlgorithm());
        assertTrue(kp.getPublic() instanceof RSAPublicKey);
        assertEquals(1024, ((RSAPublicKey) kp.getPublic()).getModulus().bitLength());
    }

    @Test
    void rsa2048() {
        KeyPairBuilder builder = new KeyPairBuilder(EncryptionAlgorithm.RSA, 2048);
        KeyPair kp = builder.build();
        assertNotNull(kp);

        assertEquals(EncryptionAlgorithm.RSA.getName(), kp.getPrivate().getAlgorithm());
        assertTrue(kp.getPrivate() instanceof RSAPrivateKey);
        assertEquals(2048, ((RSAPrivateKey) kp.getPrivate()).getModulus().bitLength());

        assertEquals(EncryptionAlgorithm.RSA.getName(), kp.getPublic().getAlgorithm());
        assertTrue(kp.getPublic() instanceof RSAPublicKey);
        assertEquals(2048, ((RSAPublicKey) kp.getPublic()).getModulus().bitLength());
    }

    @Test
    void ecdsa() {
        KeyPairBuilder builder = new KeyPairBuilder(EncryptionAlgorithm.ECDSA, 384);
        KeyPair kp = builder.build();
        assertNotNull(kp);

        assertEquals(EncryptionAlgorithm.ECDSA.getName(), kp.getPrivate().getAlgorithm());
        assertTrue(kp.getPrivate() instanceof ECPrivateKey);
        assertEquals(384, ((ECPrivateKey) kp.getPrivate()).getParams().getCurve().getField().getFieldSize());

        assertEquals(EncryptionAlgorithm.ECDSA.getName(), kp.getPublic().getAlgorithm());
        assertTrue(kp.getPublic() instanceof ECPublicKey);
        assertEquals(384, ((ECPublicKey) kp.getPublic()).getParams().getCurve().getField().getFieldSize());
    }

    @Test
    void ed25519() {
        KeyPairBuilder builder = new KeyPairBuilder(EncryptionAlgorithm.X25519, null);
        KeyPair kp = builder.build();
        assertNotNull(kp);

        assertEquals(SignatureAlgorithm.ED25519.getJCEId(), kp.getPrivate().getAlgorithm());
        assertTrue(kp.getPrivate() instanceof EdDSAPrivateKey);

        assertEquals(SignatureAlgorithm.ED25519.getJCEId(), kp.getPublic().getAlgorithm());
        assertTrue(kp.getPublic() instanceof EdDSAPublicKey);
    }

    @Test
    void ed448() {
        KeyPairBuilder builder = new KeyPairBuilder(EncryptionAlgorithm.X448, null);
        KeyPair kp = builder.build();
        assertNotNull(kp);

        assertEquals(SignatureAlgorithm.ED448.getJCEId(), kp.getPrivate().getAlgorithm());
        assertTrue(kp.getPrivate() instanceof EdDSAPrivateKey);

        assertEquals(SignatureAlgorithm.ED448.getJCEId(), kp.getPublic().getAlgorithm());
        assertTrue(kp.getPublic() instanceof EdDSAPublicKey);
    }

}
