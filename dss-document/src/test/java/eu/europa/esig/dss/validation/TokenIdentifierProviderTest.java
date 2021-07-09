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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TokenIdentifierProviderTest {

    private static CertificateToken certificate;

    @BeforeAll
    public static void init() {
        certificate = DSSUtils.loadCertificate(new File("src/test/resources/certificates/CZ.cer"));
    }

    @Test
    public void originalIdentifierProviderTest() {
        OriginalIdentifierProvider originalIdentifierProvider = new OriginalIdentifierProvider();
        assertEquals(certificate.getDSSIdAsString(), originalIdentifierProvider.getIdAsString(certificate));
    }

    @Test
    public void userFriendlyIdentifierProviderTest() {
        UserFriendlyIdentifierProvider userFriendlyIdentifierProvider = new UserFriendlyIdentifierProvider();
        String id = userFriendlyIdentifierProvider.getIdAsStringForToken(certificate);
        assertTrue(id.contains("CERTIFICATE"));
        assertTrue(id.contains(DSSUtils.replaceAllNonAlphanumericCharacters(DSSASN1Utils.getSubjectCommonName(certificate), "-")));
        assertTrue(id.contains(DSSUtils.formatDateWithCustomFormat(certificate.getNotBefore(), "yyyyMMdd-HHmm")));

        userFriendlyIdentifierProvider.setCertificatePrefix("CERT");
        id = userFriendlyIdentifierProvider.getIdAsStringForToken(certificate);
        assertTrue(id.contains("CERT"));
        assertFalse(id.contains("CERTIFICATE"));
        assertTrue(id.contains(DSSUtils.replaceAllNonAlphanumericCharacters(DSSASN1Utils.getSubjectCommonName(certificate), "-")));
        assertTrue(id.contains(DSSUtils.formatDateWithCustomFormat(certificate.getNotBefore(), "yyyyMMdd-HHmm")));

        userFriendlyIdentifierProvider.setDateFormat("yyyy-MM-dd");
        id = userFriendlyIdentifierProvider.getIdAsStringForToken(certificate);
        assertTrue(id.contains("CERT"));
        assertTrue(id.contains(DSSUtils.replaceAllNonAlphanumericCharacters(DSSASN1Utils.getSubjectCommonName(certificate), "-")));
        assertTrue(id.contains(DSSUtils.formatDateWithCustomFormat(certificate.getNotBefore(), "yyyy-MM-dd")));
        assertFalse(id.contains(DSSUtils.formatDateWithCustomFormat(certificate.getNotBefore(), "yyyyMMdd-HHmm")));
    }

}
