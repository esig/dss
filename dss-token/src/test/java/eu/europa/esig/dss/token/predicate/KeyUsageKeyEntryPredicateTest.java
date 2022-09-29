package eu.europa.esig.dss.token.predicate;

import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class KeyUsageKeyEntryPredicateTest {

    @Test
    public void rsaTest() throws IOException {
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
    public void dsaTest() throws IOException {
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
    public void ecdsaTest() throws IOException {
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
    public void ed25519Test() throws IOException {
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
    public void combinedTest() throws IOException {
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
    public void nullValueTest() {
        Exception exception = assertThrows(NullPointerException.class,
                () -> new KeyUsageKeyEntryPredicate((KeyUsageBit[]) null));
        assertEquals("KeyUsage cannot be null!", exception.getMessage());
    }

}
