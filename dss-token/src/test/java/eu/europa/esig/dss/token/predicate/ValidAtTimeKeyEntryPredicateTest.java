package eu.europa.esig.dss.token.predicate;

import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyStore;
import java.util.Calendar;
import java.util.TimeZone;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ValidAtTimeKeyEntryPredicateTest {

    @Test
    public void rsaTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/user_a_rsa.p12",
                new KeyStore.PasswordProtection("password".toCharArray()))) {

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate());
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2022, 0, 1)));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2016, 0, 1)));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2049, 0, 1)));
            assertEquals(0, signatureToken.getKeys().size());

            Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
            calendar.set(2017, 5, 8, 11, 26, 1);
            calendar.set(Calendar.MILLISECOND, 0);
            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(calendar.getTime()));
            assertEquals(1, signatureToken.getKeys().size());

            calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
            calendar.set(2017, 5, 8, 11, 26, 0);
            calendar.set(Calendar.MILLISECOND, 0);
            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(calendar.getTime()));
            assertEquals(0, signatureToken.getKeys().size());

            calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
            calendar.set(2047, 6, 4, 7, 57, 24);
            calendar.set(Calendar.MILLISECOND, 0);
            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(calendar.getTime()));
            assertEquals(1, signatureToken.getKeys().size());

            calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
            calendar.set(2047, 6, 4, 7, 57, 25);
            calendar.set(Calendar.MILLISECOND, 0);
            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(calendar.getTime()));
            assertEquals(0, signatureToken.getKeys().size());
        }
    }

    @Test
    public void dsaTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/good-dsa-user.p12",
                new KeyStore.PasswordProtection("ks-password".toCharArray()))) {

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate());
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2019, 0, 1)));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2018, 0, 1)));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2020, 0, 1)));
            assertEquals(0, signatureToken.getKeys().size());
        }
    }

    @Test
    public void ecdsaTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/good-ecdsa-user.p12",
                new KeyStore.PasswordProtection("ks-password".toCharArray()))) {

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate());
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2019, 0, 1)));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2018, 0, 1)));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2020, 0, 1)));
            assertEquals(0, signatureToken.getKeys().size());
        }
    }

    @Test
    public void ed25519Test() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/Ed25519-good-user.p12",
                new KeyStore.PasswordProtection("ks-password".toCharArray()))) {

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate());
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2022, 0, 1)));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2018, 0, 1)));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2024, 0, 1)));
            assertEquals(0, signatureToken.getKeys().size());
        }
    }

    @Test
    public void combinedTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/combined.p12",
                new KeyStore.PasswordProtection("password".toCharArray()))) {

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2017, 0, 1)));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2018, 0, 1)));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2019, 0, 1)));
            assertEquals(3, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2020, 0, 1)));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2021, 0, 1)));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2022, 0, 1)));
            assertEquals(5, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2023, 0, 1)));
            assertEquals(5, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2024, 0, 1)));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2047, 0, 1)));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2048, 0, 1)));
            assertEquals(0, signatureToken.getKeys().size());
        }
    }

    @Test
    public void nullValueTest() {
        Exception exception = assertThrows(NullPointerException.class,
                () -> new ValidAtTimeKeyEntryPredicate(null));
        assertEquals("Validation time cannot be null!", exception.getMessage());
    }

}
