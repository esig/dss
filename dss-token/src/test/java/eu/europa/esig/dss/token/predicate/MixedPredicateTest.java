package eu.europa.esig.dss.token.predicate;

import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MixedPredicateTest {

    @Test
    public void rsaTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/user_a_rsa.p12",
                new KeyStore.PasswordProtection("password".toCharArray()))) {

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.NON_REPUDIATION).and(
                    new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2016, 0, 1))));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.NON_REPUDIATION).and(
                    new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2022, 0, 1))));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.NON_REPUDIATION).and(
                    new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2049, 0, 1))));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.CRL_SIGN).and(
                    new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2016, 0, 1))));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.CRL_SIGN).and(
                    new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2022, 0, 1))));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.CRL_SIGN).and(
                    new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2049, 0, 1))));
            assertEquals(0, signatureToken.getKeys().size());
        }
    }

    @Test
    public void combinedTest() throws IOException {
        try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/combined.p12",
                new KeyStore.PasswordProtection("password".toCharArray()))) {

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.DIGITAL_SIGNATURE).and(
                    new ExtendedKeyUsageKeyEntryPredicate(ExtendedKeyUsage.SERVER_AUTH)).and(
                    new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2016, 0, 1))));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.DIGITAL_SIGNATURE).and(
                    new ExtendedKeyUsageKeyEntryPredicate(ExtendedKeyUsage.SERVER_AUTH)).and(
                    new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2022, 0, 1))));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.DIGITAL_SIGNATURE).and(
                    new ExtendedKeyUsageKeyEntryPredicate(ExtendedKeyUsage.SERVER_AUTH)).and(
                    new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2049, 0, 1))));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.DIGITAL_SIGNATURE).and(
                    new ExtendedKeyUsageKeyEntryPredicate(ExtendedKeyUsage.OCSP_SIGNING)).and(
                    new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2016, 0, 1))));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.DIGITAL_SIGNATURE).and(
                    new ExtendedKeyUsageKeyEntryPredicate(ExtendedKeyUsage.OCSP_SIGNING)).and(
                    new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2022, 0, 1))));
            assertEquals(1, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.DIGITAL_SIGNATURE).and(
                    new ExtendedKeyUsageKeyEntryPredicate(ExtendedKeyUsage.OCSP_SIGNING)).and(
                    new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2049, 0, 1))));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.NON_REPUDIATION).and(
                    new ExtendedKeyUsageKeyEntryPredicate(ExtendedKeyUsage.OCSP_SIGNING)).and(
                    new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2016, 0, 1))));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.NON_REPUDIATION).and(
                    new ExtendedKeyUsageKeyEntryPredicate(ExtendedKeyUsage.OCSP_SIGNING)).and(
                    new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2022, 0, 1))));
            assertEquals(0, signatureToken.getKeys().size());

            signatureToken.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.NON_REPUDIATION).and(
                    new ExtendedKeyUsageKeyEntryPredicate(ExtendedKeyUsage.OCSP_SIGNING)).and(
                    new ValidAtTimeKeyEntryPredicate(DSSUtils.getUtcDate(2049, 0, 1))));
            assertEquals(0, signatureToken.getKeys().size());
        }
    }

}
