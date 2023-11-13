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
import eu.europa.esig.dss.pki.jaxb.AbstractTestJaxbPKI;
import eu.europa.esig.dss.pki.x509.aia.PKIAIASource;
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
