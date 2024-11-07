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
package eu.europa.esig.dss.validation.status;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.status.RevocationFreshnessStatus;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RevocationFreshnessStatusTest {

    private static final Logger LOG = LoggerFactory.getLogger(RevocationFreshnessStatusTest.class);

    private final CertificateToken SIGNING_CERTIFICATE = DSSUtils.loadCertificate(new File("src/test/resources/certificates/good-user.cer"));
    private final CertificateToken CA_CERTIFICATE = DSSUtils.loadCertificate(new File("src/test/resources/certificates/good-ca.cer"));
    private final CertificateToken TST_CERTIFICATE = DSSUtils.loadCertificate(new File("src/test/resources/certificates/CZ.cer"));

    private final String ERROR_MESSAGE = "Revocation is not fresh!";
    private final String CERT_ONE_MESSAGE = "No fresh revocation data found!";
    private final String CERT_TWO_MESSAGE = "No updated revocation data found!";
    private final String CERT_THREE_MESSAGE = "No new revocation data found!";

    @Test
    void test() {
        RevocationFreshnessStatus status = new RevocationFreshnessStatus();

        status.addTokenAndRevocationNextUpdateTime(SIGNING_CERTIFICATE, DSSUtils.getUtcDate(2022, 0, 1));
        status.addTokenAndRevocationNextUpdateTime(CA_CERTIFICATE, DSSUtils.getUtcDate(2022, 6, 1));
        status.addTokenAndRevocationNextUpdateTime(TST_CERTIFICATE, DSSUtils.getUtcDate(2022, 0, 10));

        assertNotNull(status.getTokenRevocationNextUpdateTime(SIGNING_CERTIFICATE));
        assertNotNull(status.getTokenRevocationNextUpdateTime(CA_CERTIFICATE));
        assertNotNull(status.getTokenRevocationNextUpdateTime(TST_CERTIFICATE));

        Date minimalNextUpdateTime = status.getMinimalNextUpdateTime();
        assertNotNull(minimalNextUpdateTime);
        assertEquals(DSSUtils.getUtcDate(2022, 6, 1), minimalNextUpdateTime);

        status.addRelatedTokenAndErrorMessage(SIGNING_CERTIFICATE, CERT_ONE_MESSAGE);
        status.addRelatedTokenAndErrorMessage(CA_CERTIFICATE, CERT_TWO_MESSAGE);
        status.addRelatedTokenAndErrorMessage(TST_CERTIFICATE, CERT_THREE_MESSAGE);

        assertNotNull(status.getMessageForToken(SIGNING_CERTIFICATE));
        assertNotNull(status.getMessageForToken(CA_CERTIFICATE));
        assertNotNull(status.getMessageForToken(TST_CERTIFICATE));

        assertNotNull(status.getMessageForObjectWithId(SIGNING_CERTIFICATE.getDSSIdAsString()));
        assertNotNull(status.getMessageForObjectWithId(CA_CERTIFICATE.getDSSIdAsString()));
        assertNotNull(status.getMessageForObjectWithId(TST_CERTIFICATE.getDSSIdAsString()));

        status.setMessage(ERROR_MESSAGE);
        assertNotNull(status.getMessage());

        String errorString = status.getErrorString();
        assertNotNull(errorString);

        assertTrue(errorString.contains(ERROR_MESSAGE));
        assertTrue(errorString.contains(CERT_ONE_MESSAGE));
        assertTrue(errorString.contains(CERT_TWO_MESSAGE));
        assertTrue(errorString.contains(CERT_THREE_MESSAGE));

        assertTrue(errorString.contains(SIGNING_CERTIFICATE.getDSSIdAsString()));
        assertTrue(errorString.contains(CA_CERTIFICATE.getDSSIdAsString()));
        assertTrue(errorString.contains(TST_CERTIFICATE.getDSSIdAsString()));

        assertTrue(errorString.contains(DSSUtils.formatDateToRFC(DSSUtils.getUtcDate(2022, 6, 1))));

        LOG.info(errorString);
    }

}
