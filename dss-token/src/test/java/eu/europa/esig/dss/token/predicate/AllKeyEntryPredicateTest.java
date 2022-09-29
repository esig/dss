package eu.europa.esig.dss.token.predicate;

import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class AllKeyEntryPredicateTest {

    @Test
    public void rsaTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/user_a_rsa.p12",
                new KeyStore.PasswordProtection("password".toCharArray()))) {
            signatureToken.setKeyEntryPredicate(new AllKeyEntryPredicate());
            assertEquals(1, signatureToken.getKeys().size());
        }
    }

    @Test
    public void dsaTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/good-dsa-user.p12",
                new KeyStore.PasswordProtection("ks-password".toCharArray()))) {
            signatureToken.setKeyEntryPredicate(new AllKeyEntryPredicate());
            assertEquals(1, signatureToken.getKeys().size());
        }
    }

    @Test
    public void ecdsaTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/good-ecdsa-user.p12",
                new KeyStore.PasswordProtection("ks-password".toCharArray()))) {
            signatureToken.setKeyEntryPredicate(new AllKeyEntryPredicate());
            assertEquals(1, signatureToken.getKeys().size());
        }
    }

    @Test
    public void ed25519Test() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/Ed25519-good-user.p12",
                new KeyStore.PasswordProtection("ks-password".toCharArray()))) {
            signatureToken.setKeyEntryPredicate(new AllKeyEntryPredicate());
            assertEquals(1, signatureToken.getKeys().size());
        }
    }

    @Test
    public void combinedTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/combined.p12",
                new KeyStore.PasswordProtection("password".toCharArray()))) {
            signatureToken.setKeyEntryPredicate(new AllKeyEntryPredicate());
            assertEquals(7, signatureToken.getKeys().size());
        }
    }

    @Test
    public void nullPredicateTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/user_a_rsa.p12",
                new KeyStore.PasswordProtection("password".toCharArray()))) {

            Exception exception = assertThrows(Exception.class, () -> signatureToken.setKeyEntryPredicate(null));
            assertEquals("Key entry predicate cannot be null!", exception.getMessage());
        }
    }

}
