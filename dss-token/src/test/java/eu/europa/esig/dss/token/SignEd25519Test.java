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
package eu.europa.esig.dss.token;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore.PasswordProtection;
import java.security.Signature;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignEd25519Test {

    private static final Logger LOG = LoggerFactory.getLogger(SignEd25519Test.class);

    @Test
    void test() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/Ed25519-good-user.p12",
                new PasswordProtection("ks-password".toCharArray()))) {
            List<DSSPrivateKeyEntry> keys = signatureToken.getKeys();
            KSPrivateKeyEntry entry = (KSPrivateKeyEntry) keys.get(0);

            ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes(StandardCharsets.UTF_8));

            SignatureValue signValue = signatureToken.sign(toBeSigned, DigestAlgorithm.SHA512, entry);
            assertNotNull(signValue.getAlgorithm());
            LOG.info("Sig value : {}", Base64.getEncoder().encodeToString(signValue.getValue()));
            try {
                Signature sig = Signature.getInstance(signValue.getAlgorithm().getJCEId());
                sig.initVerify(entry.getCertificate().getPublicKey());
                sig.update(toBeSigned.getBytes());
                assertTrue(sig.verify(signValue.getValue()));
            } catch (GeneralSecurityException e) {
                Assertions.fail(e.getMessage());
            }
        }
    }

    @Test
    void testSignatureAlgorithm() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/Ed25519-good-user.p12",
                new PasswordProtection("ks-password".toCharArray()))) {
            List<DSSPrivateKeyEntry> keys = signatureToken.getKeys();
            KSPrivateKeyEntry entry = (KSPrivateKeyEntry) keys.get(0);

            ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes(StandardCharsets.UTF_8));

            SignatureValue signValue = signatureToken.sign(toBeSigned, SignatureAlgorithm.ED25519, entry);
            assertNotNull(signValue.getAlgorithm());
            LOG.info("Sig value : {}", Base64.getEncoder().encodeToString(signValue.getValue()));
            try {
                Signature sig = Signature.getInstance(signValue.getAlgorithm().getJCEId());
                sig.initVerify(entry.getCertificate().getPublicKey());
                sig.update(toBeSigned.getBytes());
                assertTrue(sig.verify(signValue.getValue()));
            } catch (GeneralSecurityException e) {
                Assertions.fail(e.getMessage());
            }
        }
    }

    @Test
    void testSignWithWrongSignatureAlgorithm() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/Ed25519-good-user.p12",
                new PasswordProtection("ks-password".toCharArray()))) {
            List<DSSPrivateKeyEntry> keys = signatureToken.getKeys();
            KSPrivateKeyEntry entry = (KSPrivateKeyEntry) keys.get(0);

            ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes(StandardCharsets.UTF_8));

            Exception exception = assertThrows(IllegalArgumentException.class, () ->
                    signatureToken.sign(toBeSigned, SignatureAlgorithm.RSA_SHA512, entry));
            assertEquals("The provided SignatureAlgorithm 'RSA with SHA512' cannot be used to sign with " +
                            "the token's implied EncryptionAlgorithm 'EdDSA'", exception.getMessage());
        }
    }

    @Test
    void testDigestSign() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/Ed25519-good-user.p12",
                new PasswordProtection("ks-password".toCharArray()))) {
            List<DSSPrivateKeyEntry> keys = signatureToken.getKeys();
            KSPrivateKeyEntry entry = (KSPrivateKeyEntry) keys.get(0);

            ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes(StandardCharsets.UTF_8));

            DigestAlgorithm digestAlgo = DigestAlgorithm.SHA512;

            // Important step with RSA without PSS
            final byte[] digestBinaries = DSSUtils.digest(digestAlgo, toBeSigned.getBytes());
            final byte[] encodedDigest = DSSUtils.encodeRSADigest(digestAlgo, digestBinaries);
            Digest digest = new Digest(digestAlgo, encodedDigest);

            Exception exception = assertThrows(UnsupportedOperationException.class, () -> signatureToken.signDigest(digest, entry));
            assertEquals("The SignatureAlgorithm for digest signing is not found for the given configuration " +
                    "[EncryptionAlgorithm: EDDSA]", exception.getMessage());

            exception = assertThrows(UnsupportedOperationException.class, () -> signatureToken.signDigest(digest, SignatureAlgorithm.ED25519, entry));
            assertEquals("The SignatureAlgorithm for digest signing is not found for the given configuration " +
                    "[EncryptionAlgorithm: EDDSA]", exception.getMessage());
        }
    }

}
