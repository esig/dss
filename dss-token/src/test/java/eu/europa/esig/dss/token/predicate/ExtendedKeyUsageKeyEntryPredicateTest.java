package eu.europa.esig.dss.token.predicate;

import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ExtendedKeyUsageKeyEntryPredicateTest {

    @Test
    public void rsaTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/user_a_rsa.p12",
                new KeyStore.PasswordProtection("password".toCharArray()))) {

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate((ExtendedKeyUsage) null));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate(new ExtendedKeyUsage[]{ null }));
            assertEquals(0, signatureToken.getKeys().size());
        }
    }

    @Test
    public void dsaTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/good-dsa-user.p12",
                new KeyStore.PasswordProtection("ks-password".toCharArray()))) {

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate((ExtendedKeyUsage) null));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate(new ExtendedKeyUsage[]{ null }));
            assertEquals(0, signatureToken.getKeys().size());
        }
    }

    @Test
    public void ecdsaTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/good-ecdsa-user.p12",
                new KeyStore.PasswordProtection("ks-password".toCharArray()))) {

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate((ExtendedKeyUsage) null));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate(new ExtendedKeyUsage[]{ null }));
            assertEquals(0, signatureToken.getKeys().size());
        }
    }

    @Test
    public void ed25519Test() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/Ed25519-good-user.p12",
                new KeyStore.PasswordProtection("ks-password".toCharArray()))) {

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate((ExtendedKeyUsage) null));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate(new ExtendedKeyUsage[]{ null }));
            assertEquals(0, signatureToken.getKeys().size());
        }
    }

    @Test
    public void combinedTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/combined.p12",
                new KeyStore.PasswordProtection("password".toCharArray()))) {
            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate(ExtendedKeyUsage.OCSP_SIGNING));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate(ExtendedKeyUsage.TIMESTAMPING));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate(ExtendedKeyUsage.OCSP_SIGNING, ExtendedKeyUsage.TIMESTAMPING));
            assertEquals(2, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate(ExtendedKeyUsage.SERVER_AUTH));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate(ExtendedKeyUsage.SERVER_AUTH, ExtendedKeyUsage.OCSP_SIGNING));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate((ExtendedKeyUsage) null));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate(new ExtendedKeyUsage[]{ null }));
            assertEquals(0, signatureToken.getKeys().size());
        }
    }

    @Test
    public void combinedWithStringsTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/combined.p12",
                new KeyStore.PasswordProtection("password".toCharArray()))) {
            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate("1.3.6.1.5.5.7.3.9"));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate("1.3.6.1.5.5.7.3.8"));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate("1.3.6.1.5.5.7.3.9", "1.3.6.1.5.5.7.3.8"));
            assertEquals(2, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate("1.3.6.1.5.5.7.3.1"));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.9"));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate((String) null));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate(new String[]{ null }));
            assertEquals(0, signatureToken.getKeys().size());
        }
    }

    @Test
    public void nullValueTest() {
        Exception exception = assertThrows(NullPointerException.class,
                () -> new ExtendedKeyUsageKeyEntryPredicate((ExtendedKeyUsage[]) null));
        assertEquals("ExtendedKeyUsage cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class,
                () -> new ExtendedKeyUsageKeyEntryPredicate((String[]) null));
        assertEquals("ExtendedKeyUsage OIDs cannot be null!", exception.getMessage());
    }
    
}
