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
package eu.europa.esig.dss.token.predicate;

import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KeyUsageKeyEntryPredicateTest {

    @Test
    void rsaTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/user_a_rsa.p12",
                new KeyStore.PasswordProtection("password".toCharArray()))) {
            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.NON_REPUDIATION));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.DIGITAL_SIGNATURE));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.NON_REPUDIATION, KeyUsageBit.DIGITAL_SIGNATURE));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.KEY_CERT_SIGN));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.CRL_SIGN));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.KEY_CERT_SIGN, KeyUsageBit.CRL_SIGN));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate((KeyUsageBit) null));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(new KeyUsageBit[]{ null }));
            assertEquals(0, signatureToken.getKeys().size());
        }
    }

    @Test
    void dsaTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/good-dsa-user.p12",
                new KeyStore.PasswordProtection("ks-password".toCharArray()))) {
            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.NON_REPUDIATION));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.DIGITAL_SIGNATURE));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.NON_REPUDIATION, KeyUsageBit.DIGITAL_SIGNATURE));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.KEY_CERT_SIGN));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.CRL_SIGN));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.KEY_CERT_SIGN, KeyUsageBit.CRL_SIGN));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate((KeyUsageBit) null));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(new KeyUsageBit[]{ null }));
            assertEquals(0, signatureToken.getKeys().size());
        }
    }

    @Test
    void ecdsaTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/good-ecdsa-user.p12",
                new KeyStore.PasswordProtection("ks-password".toCharArray()))) {
            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.NON_REPUDIATION));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.DIGITAL_SIGNATURE));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.NON_REPUDIATION, KeyUsageBit.DIGITAL_SIGNATURE));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.KEY_CERT_SIGN));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.CRL_SIGN));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.KEY_CERT_SIGN, KeyUsageBit.CRL_SIGN));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate((KeyUsageBit) null));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(new KeyUsageBit[]{ null }));
            assertEquals(0, signatureToken.getKeys().size());
        }
    }

    @Test
    void ed25519Test() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/Ed25519-good-user.p12",
                new KeyStore.PasswordProtection("ks-password".toCharArray()))) {
            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.NON_REPUDIATION));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.DIGITAL_SIGNATURE));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.NON_REPUDIATION, KeyUsageBit.DIGITAL_SIGNATURE));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.KEY_CERT_SIGN));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.CRL_SIGN));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.KEY_CERT_SIGN, KeyUsageBit.CRL_SIGN));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate((KeyUsageBit) null));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(new KeyUsageBit[]{ null }));
            assertEquals(0, signatureToken.getKeys().size());
        }
    }

    @Test
    void combinedTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/combined.p12",
                new KeyStore.PasswordProtection("password".toCharArray()))) {
            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.NON_REPUDIATION));
            assertEquals(4, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.DIGITAL_SIGNATURE));
            assertEquals(3, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.NON_REPUDIATION, KeyUsageBit.DIGITAL_SIGNATURE));
            assertEquals(6, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.KEY_CERT_SIGN));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.CRL_SIGN));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.KEY_CERT_SIGN, KeyUsageBit.CRL_SIGN));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate((KeyUsageBit) null));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(new KeyUsageBit[]{ null }));
            assertEquals(0, signatureToken.getKeys().size());
        }
    }

    @Test
    void nullValueTest() {
        Exception exception = assertThrows(NullPointerException.class,
                () -> new KeyUsageKeyEntryPredicate((KeyUsageBit[]) null));
        assertEquals("KeyUsage cannot be null!", exception.getMessage());
    }

}
