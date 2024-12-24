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
package eu.europa.esig.dss.spi.x509.revocation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ListRevocationSourceTest {

    private static final CertificateToken CERT = DSSUtils.loadCertificate(new File("src/test/resources/sk_user.cer"));

    private static final CertificateToken CA_CERT = DSSUtils.loadCertificate(new File("src/test/resources/sk_ca.cer"));

    private static final DSSDocument OCSP_DOCUMENT = new FileDocument("src/test/resources/sk_ocsp.bin");

    private static final DSSDocument WRONG_OCSP_DOCUMENT = new FileDocument("src/test/resources/peru_ocsp.bin");

    @Test
    void multipleRevocationSourcesTest() {
        ListRevocationSource<OCSP> lrs = new ListRevocationSource<>();
        assertEquals(0, lrs.getNumberOfSources());
        assertEquals(0, lrs.getAllRevocationBinaries().size());
        assertEquals(0, lrs.getRevocationTokens(CERT, CA_CERT).size());

        ExternalResourcesOCSPSource ocspSource = new ExternalResourcesOCSPSource(OCSP_DOCUMENT);
        assertTrue(lrs.add(ocspSource));

        assertEquals(1, lrs.getNumberOfSources());
        assertEquals(1, lrs.getAllRevocationBinaries().size());
        assertEquals(1, lrs.getRevocationTokens(CERT, CA_CERT).size());

        ExternalResourcesOCSPSource ocspSourceTwo = new ExternalResourcesOCSPSource(OCSP_DOCUMENT);
        assertTrue(lrs.add(ocspSourceTwo));

        assertEquals(2, lrs.getNumberOfSources());
        assertEquals(1, lrs.getAllRevocationBinaries().size());
        assertEquals(1, lrs.getRevocationTokens(CERT, CA_CERT).size());

        ExternalResourcesOCSPSource ocspSourceThree = new ExternalResourcesOCSPSource(WRONG_OCSP_DOCUMENT);
        assertTrue(lrs.add(ocspSourceThree));

        assertEquals(3, lrs.getNumberOfSources());
        assertEquals(2, lrs.getAllRevocationBinaries().size());
        assertEquals(1, lrs.getRevocationTokens(CERT, CA_CERT).size());

        assertFalse(lrs.add(ocspSource));
        assertFalse(lrs.add(ocspSourceTwo));
        assertFalse(lrs.add(ocspSourceThree));
        assertEquals(3, lrs.getNumberOfSources());
    }

}
