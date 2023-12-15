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
package eu.europa.esig.dss.pki.jaxb.aia;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.exception.PKIException;
import eu.europa.esig.dss.pki.jaxb.AbstractTestJaxbPKI;
import eu.europa.esig.dss.pki.x509.aia.PKIAIASource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class JaxbPKIAIASourceTest extends AbstractTestJaxbPKI {

    private static CertificateToken goodUser;
    private static CertificateToken goodCa;

    @BeforeAll
    public static void init() {
        goodUser = repository.getCertEntityBySubject("good-user").getCertificateToken();
        goodCa = repository.getCertEntityBySubject("root-ca").getCertificateToken();
    }

    @Test
    public void testCompleteCertChain() {
        PKIAIASource aiaSource = new PKIAIASource(repository);
        aiaSource.setCompleteCertificateChain(true);

        Collection<CertificateToken> certChain = aiaSource.getCertificatesByAIA(goodUser);
        assertTrue(Utils.isCollectionNotEmpty(certChain));
        assertEquals(2, certChain.size());

        boolean foundIssuer = false;
        for (CertificateToken issuer : certChain) {
            if (goodUser.isSignedBy(issuer)) {
                foundIssuer = true;
            }
        }
        assertTrue(foundIssuer);
    }

    @Test
    public void testLoadIssuer() {
        PKIAIASource aiaSource = new PKIAIASource(repository);
        aiaSource.setCompleteCertificateChain(false);

        Collection<CertificateToken> certChain = aiaSource.getCertificatesByAIA(goodUser);
        assertTrue(Utils.isCollectionNotEmpty(certChain));
        assertEquals(1, certChain.size());
        assertTrue(goodUser.isSignedBy(certChain.iterator().next()));
    }

    @Test
    public void testLoadIssuerNoAIA() {
        PKIAIASource aiaSource = new PKIAIASource(repository);
        aiaSource.setCompleteCertificateChain(true);
        Collection<CertificateToken> issuers = aiaSource.getCertificatesByAIA(goodCa);
        assertTrue(Utils.isCollectionEmpty(issuers));
    }

    @Test
    public void testWrongCert() {
        PKIAIASource aiaSource = new PKIAIASource(repository);
        aiaSource.setCompleteCertificateChain(true);
        CertificateToken cert = DSSUtils.loadCertificateFromBase64EncodedString("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");
        Exception exception = assertThrows(PKIException.class, () -> aiaSource.getCertificatesByAIA(cert));
        assertEquals("CertEntity for certificate token with " +
                "Id 'C-C670C79BF277AF7E7B34A6AA4FA304441833C6BD01A70A7E9B7A2D94C1C1F926' not found in the repository!", exception.getMessage());
    }

    @Test
    public void setNullRepositoryTest() {
        Exception exception = assertThrows(NullPointerException.class, () -> new PKIAIASource(null));
        assertEquals("Certificate repository shall be provided!", exception.getMessage());
    }

    @Test
    public void setNullCertificateTokenTest() {
        PKIAIASource aiaSource = new PKIAIASource(repository);
        Exception exception = assertThrows(NullPointerException.class, () -> aiaSource.getCertificatesByAIA(null));
        assertEquals("Certificate Token parameter is not provided!", exception.getMessage());
    }

}
