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
