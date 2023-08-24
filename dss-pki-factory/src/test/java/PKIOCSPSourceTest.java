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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.db.JaxbCertEntityRepository;
import eu.europa.esig.dss.pki.exception.Error404Exception;
import eu.europa.esig.dss.pki.factory.GenericFactory;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.DBCertEntity;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.pki.x509.revocation.ocsp.PKIOCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

public class PKIOCSPSourceTest {

    private static CertificateToken certificateToken;
    private static CertificateToken rootToken;

    private static CertificateToken goodUser;
    private static CertificateToken goodUserOCSPWithReqCertId;
    private static CertificateToken goodCa;
    private static CertificateToken ed25519goodUser;
    private static CertificateToken ed25519goodCa;
    static CertEntityRepository<DBCertEntity> certificateEntityService = GenericFactory.getInstance().create(JaxbCertEntityRepository.class);
    private static CertEntity certEntity;
    private static CertificateToken revokedCa;
    private static CertificateToken revokedUser;

    @BeforeAll
    public static void init() {
        certEntity = certificateEntityService.getCertEntity("good-user");
        rootToken = certificateEntityService.getCertEntity("root-ca").getCertificateToken();


        goodUser = certEntity.getCertificateToken();
        certificateToken = certEntity.getCertificateToken();
        goodUserOCSPWithReqCertId = certificateEntityService.getCertEntity("good-user-ocsp-certid-digest").getCertificateToken();
        goodCa = certEntity.getCertificateToken();
        ed25519goodUser = certificateEntityService.getCertEntity("Ed25519-good-user").getCertificateToken();
        ed25519goodCa = certificateEntityService.getCertEntity("Ed25519-good-ca").getCertificateToken();
        revokedCa = certificateEntityService.getCertEntity("revoked-ca").getCertificateToken();
        revokedUser = certificateEntityService.getCertEntity("revoked-user").getCertificateToken();
    }

    @Test
    public void testOCSPWithoutNonce() {
        PKIOCSPSource ocspSource = new PKIOCSPSource(certificateEntityService, certEntity);
        OCSPToken ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
    }

    @Test
    public void testOCSP() {

        PKIOCSPSource ocspSource = new PKIOCSPSource(certificateEntityService, certEntity);
        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
        System.out.println(ocspToken.toString());
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
    }
  @Test
    public void testOCSPRevoked() {

        PKIOCSPSource ocspSource = new PKIOCSPSource(certificateEntityService);
        OCSPToken ocspToken = ocspSource.getRevocationToken(revokedCa,revokedCa);

        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
    }


    @Test
    public void testWithSetDataLoader() {
        PKIOCSPSource ocspSource = new PKIOCSPSource(certificateEntityService);
        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
    }

    @Test
    public void testOCSPEd25519() {
        PKIOCSPSource ocspSource = new PKIOCSPSource(certificateEntityService);
        ocspSource.setDigestAlgorithm(DigestAlgorithm.SHA512);
        Exception exception = assertThrows(Error404Exception.class, () -> ocspSource.getRevocationToken(ed25519goodUser, ed25519goodCa));
        assertTrue(exception.getMessage().contains("not found for CA '"));

    }

    @Test
    public void testOCSPWithNonce() {
        PKIOCSPSource ocspSource = new PKIOCSPSource(certificateEntityService, certEntity);
        ocspSource.setProductionDate(new Date());
        OCSPToken ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
        assertNotNull(ocspToken);
    }

    @Test
    public void customCertIDDigestAlgorithmTest() {

        PKIOCSPSource ocspSource = new PKIOCSPSource(certificateEntityService);
        ocspSource.setDigestAlgorithm(DigestAlgorithm.SHA1);
        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
        assertNotNull(ocspToken);
        assertEquals(SignatureAlgorithm.RSA_SHA1, ocspToken.getSignatureAlgorithm()); // default value

        ocspSource.setDigestAlgorithm(DigestAlgorithm.SHA256);
        ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
        assertEquals(SignatureAlgorithm.RSA_SHA256, ocspToken.getSignatureAlgorithm());

        ocspSource.setDigestAlgorithm(DigestAlgorithm.SHA512);
        ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
        assertEquals(SignatureAlgorithm.RSA_SHA512, ocspToken.getSignatureAlgorithm());

        ocspSource.setDigestAlgorithm(DigestAlgorithm.SHA3_256);
        ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
        assertEquals(SignatureAlgorithm.RSA_SHA3_256, ocspToken.getSignatureAlgorithm());

        ocspSource.setDigestAlgorithm(DigestAlgorithm.SHA3_512);
        ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
        assertEquals(SignatureAlgorithm.RSA_SHA3_512, ocspToken.getSignatureAlgorithm());
    }


}
