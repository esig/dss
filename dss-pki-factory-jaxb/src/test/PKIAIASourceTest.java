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

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.jaxb.db.JaxbCertEntityRepository;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.pki.x509.aia.PKIAIASource;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Collection;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class PKIAIASourceTest {

    private static CertificateToken certificateWithAIA;
    private static CertificateToken goodCaTrusted;
    private static final CertEntityRepository certEntityRepository = new JaxbCertEntityRepository();
    private static CertEntity certEntity;

    @BeforeAll
    public static void init() {
        certEntity = certEntityRepository.getCertEntityBySubject("good-user");
        certificateWithAIA = certEntity.getCertificateToken();
        goodCaTrusted = certEntityRepository.getCertEntityBySubject("root-ca").getCertificateToken();
        assertNotNull(certificateWithAIA);
    }

    @Test
    public void testLoadIssuer() {
        PKIAIASource aiaSource = new PKIAIASource(certEntityRepository);
        aiaSource.setCompleteCertificateChain(true);
        CertificateToken certificateToken = certEntityRepository.getCertEntityBySubject("John Doe").getCertificateToken();
        Collection<CertificateToken> issuers = aiaSource.getCertificatesByAIA(certificateToken);

        assertTrue(Utils.isCollectionNotEmpty(issuers));
        boolean foundIssuer = false;
        for (CertificateToken issuer : issuers) {
            if (certificateToken.isSignedBy(issuer)) {
                foundIssuer = true;
            }
        }
        assertTrue(foundIssuer);
    }

    @Test
    public void setNullCertEntityRepositoryTest() {
        PKIAIASource aiaSource = new PKIAIASource(null);
        Exception exception = assertThrows(NullPointerException.class, () -> aiaSource.getCertificatesByAIA(certificateWithAIA));
        assertEquals("CertEntity Repository is not provided", exception.getMessage());
    }

    @Test
    public void setNullCertificateTokenTest() {
        PKIAIASource aiaSource = new PKIAIASource(certEntityRepository);
        Exception exception = assertThrows(NullPointerException.class, () -> aiaSource.getCertificatesByAIA(null));
        assertEquals("CertificateToken parameter cannot be null", exception.getMessage());
    }

    @Test
    public void emptyAcceptedProtocolsTest() {
        PKIAIASource aiaSource = new PKIAIASource(certEntityRepository);
        Collection<CertificateToken> issuers = aiaSource.getCertificatesByAIA(certificateWithAIA);
        assertFalse(Utils.isCollectionEmpty(issuers));
    }

    @Test
    public void testLoadIssuerNoAIA() {
        PKIAIASource aiaSource = new PKIAIASource(certEntityRepository);
        aiaSource.setCompleteCertificateChain(true);
        Collection<CertificateToken> issuers = aiaSource.getCertificatesByAIA(goodCaTrusted);
        assertTrue(Utils.isCollectionEmpty(issuers));
        assertTrue(goodCaTrusted.isCA());
    }

    @Test
    public void acceptedProtocolsTest() {
        CertificateToken certificate = certEntityRepository.getCertEntityBySubject("ocsp-skip-root-ca").getCertificateToken(); //src/test/resources/sk_ca.cer
        Collection<CertificateToken> issuers = new HashSet<>();
        if (CertificateExtensionsUtils.getAuthorityInformationAccess(certificate) != null) {
            PKIAIASource aiaSource = new PKIAIASource(certEntityRepository);
            issuers = aiaSource.getCertificatesByAIA(certificate);

        }

        assertEquals(0, issuers.size());

    }

}
