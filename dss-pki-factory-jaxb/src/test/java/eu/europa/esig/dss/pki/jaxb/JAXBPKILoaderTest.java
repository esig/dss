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
package eu.europa.esig.dss.pki.jaxb;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.QCTypeEnum;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.extension.CertificatePolicies;
import eu.europa.esig.dss.model.x509.extension.QcStatements;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntity;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JAXBPKILoaderTest extends AbstractTestJaxbPKI {

    @Test
    void certificatesTest() {
        JAXBCertEntity goodUser = repository.getCertEntityBySubject("good-user");
        assertEquals(10, goodUser.getSerialNumber());
        assertEquals("good-user", goodUser.getSubject());

        CertificateToken goodUserCertificate = goodUser.getCertificateToken();
        assertNotNull(goodUserCertificate);

        assertTrue(goodUserCertificate.getNotBefore().before(new Date()));
        assertTrue(goodUserCertificate.getNotAfter().after(new Date()));

        assertEquals(EncryptionAlgorithm.RSA.getName(), goodUserCertificate.getPublicKey().getAlgorithm());
        assertTrue(goodUserCertificate.getPublicKey() instanceof RSAPublicKey);
        assertEquals(2048, ((RSAPublicKey) goodUserCertificate.getPublicKey()).getModulus().bitLength());

        assertEquals(1, goodUserCertificate.getKeyUsageBits().size());
        assertEquals(KeyUsageBit.NON_REPUDIATION, goodUserCertificate.getKeyUsageBits().get(0));

        assertFalse(Utils.isCollectionNotEmpty(CertificateExtensionsUtils.getExtendedKeyUsage(goodUserCertificate).getOids()));

        assertFalse(CertificateExtensionsUtils.getBasicConstraints(goodUserCertificate).isCa());
        assertNull(CertificateExtensionsUtils.getOcspNoCheck(goodUserCertificate));

        assertFalse(Utils.isCollectionNotEmpty(CertificateExtensionsUtils.getCRLAccessUrls(goodUserCertificate)));
        assertTrue(Utils.isCollectionNotEmpty(CertificateExtensionsUtils.getOCSPAccessUrls(goodUserCertificate)));
        assertTrue(Utils.isCollectionNotEmpty(CertificateExtensionsUtils.getCAIssuersAccessUrls(goodUserCertificate)));

        JAXBCertEntity goodCa = repository.getCertEntityBySubject("good-ca");
        assertEquals(4, goodCa.getSerialNumber());
        assertEquals("good-ca", goodCa.getSubject());

        CertificateToken goodCaCertificate = goodCa.getCertificateToken();

        assertTrue(goodUserCertificate.isSignedBy(goodCaCertificate));

        JAXBCertEntity issuer = goodUser.getIssuer();
        assertEquals(goodCa, issuer);

        List<CertificateToken> certificateChain = goodUser.getCertificateChain();
        assertEquals(3, certificateChain.size());
        assertTrue(certificateChain.contains(goodCaCertificate));
        assertTrue(certificateChain.contains(goodUserCertificate));

        assertEquals(2, goodCaCertificate.getKeyUsageBits().size());
        assertTrue(goodCaCertificate.getKeyUsageBits().contains(KeyUsageBit.KEY_CERT_SIGN));
        assertTrue(goodCaCertificate.getKeyUsageBits().contains(KeyUsageBit.CRL_SIGN));

        assertTrue(CertificateExtensionsUtils.getBasicConstraints(goodCaCertificate).isCa());

        PrivateKey privateKey = goodUser.getPrivateKey();
        assertNotNull(privateKey);
        assertEquals(EncryptionAlgorithm.RSA.getName(), privateKey.getAlgorithm());
        assertTrue(goodUserCertificate.getPublicKey() instanceof RSAPublicKey);
        assertEquals(2048, ((RSAPrivateKey) privateKey).getModulus().bitLength());

        assertEquals(10, goodUserCertificate.getSerialNumber().intValue());
        assertEquals("good-user", DSSASN1Utils.getSubjectCommonName(goodUserCertificate));

        assertNull(goodUser.getRevocationDate());
        assertNull(goodUser.getRevocationReason());

        assertEquals("good-pki", goodUser.getPkiName());

        assertNull(goodUser.getOcspResponder());
        assertFalse(goodUser.isTrustAnchor());

        assertTrue(Utils.isCollectionNotEmpty(CertificateExtensionsUtils.getCRLAccessUrls(goodCaCertificate)));
        assertFalse(Utils.isCollectionNotEmpty(CertificateExtensionsUtils.getOCSPAccessUrls(goodCaCertificate)));
        assertTrue(Utils.isCollectionNotEmpty(CertificateExtensionsUtils.getCAIssuersAccessUrls(goodCaCertificate)));

        assertNotNull(goodCa.getOcspResponder());
        assertFalse(goodCa.isTrustAnchor());

        JAXBCertEntity ocspResponder = goodCa.getOcspResponder();

        assertEquals(2, ocspResponder.getSerialNumber());
        assertEquals("ocsp-responder", ocspResponder.getSubject());

        CertificateToken ocspResponderCertificate = ocspResponder.getCertificateToken();
        assertTrue(ocspResponderCertificate.isSignedBy(goodCaCertificate));

        assertEquals(ExtendedKeyUsage.OCSP_SIGNING.getOid(), CertificateExtensionsUtils.getExtendedKeyUsage(ocspResponderCertificate).getOids().get(0));
        assertNotNull(CertificateExtensionsUtils.getOcspNoCheck(ocspResponderCertificate));
        assertTrue(CertificateExtensionsUtils.getOcspNoCheck(ocspResponderCertificate).isOcspNoCheck());

        JAXBCertEntity rootCa = repository.getCertEntityBySubject("root-ca");

        assertEquals(1, rootCa.getSerialNumber());
        assertEquals("root-ca", rootCa.getSubject());

        assertTrue(rootCa.isTrustAnchor());
        assertTrue(goodCaCertificate.isSignedBy(rootCa.getCertificateToken()));

        JAXBCertEntity revokedUser = repository.getCertEntityBySubject("revoked-user");
        assertEquals(12, revokedUser.getSerialNumber());
        assertEquals("revoked-user", revokedUser.getSubject());

        assertNotNull(revokedUser.getRevocationDate());
        assertEquals(RevocationReason.KEY_COMPROMISE, revokedUser.getRevocationReason());

        JAXBCertEntity pseudoUser = repository.getCertEntityBySubject("good-user-with-pseudo");
        assertEquals(22, pseudoUser.getSerialNumber());
        assertEquals("good-user-with-pseudo", pseudoUser.getSubject());

        assertEquals("user-pseudo",
                DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.PSEUDONYM, pseudoUser.getCertificateToken().getSubject()));
    }

    @Test
    void crossCertificatesTest() {
        JAXBCertEntity firstCrossCertificate = repository.getCertEntityBySerialNumberAndParentSubject(2002L, "external-ca");
        JAXBCertEntity secondCrossCertificate = repository.getCertEntityBySerialNumberAndParentSubject(2003L, "cc-root-ca");
        JAXBCertEntity thirdCrossCertificate = repository.getCertEntityBySerialNumberAndParentSubject(2004L, "cc-root-ca-alt");
        assertArrayEquals(firstCrossCertificate.getCertificateToken().getPublicKey().getEncoded(),
                secondCrossCertificate.getCertificateToken().getPublicKey().getEncoded());
        assertArrayEquals(firstCrossCertificate.getCertificateToken().getPublicKey().getEncoded(),
                thirdCrossCertificate.getCertificateToken().getPublicKey().getEncoded());

        JAXBCertEntity firstCrossCertificateIssuer = repository.getCertEntityBySerialNumberAndParentSubject(2001L, "external-root-ca");
        JAXBCertEntity secondCrossCertificateIssuer = repository.getCertEntityBySerialNumberAndParentSubject(2003L, "cc-root-ca");
        JAXBCertEntity thirdCrossCertificateIssuer = repository.getCertEntityBySerialNumberAndParentSubject(2004L, "cc-root-ca-alt");

        assertTrue(firstCrossCertificate.getCertificateToken().isSignedBy(firstCrossCertificateIssuer.getCertificateToken()));
        assertFalse(firstCrossCertificate.getCertificateToken().isSignedBy(secondCrossCertificateIssuer.getCertificateToken()));
        assertTrue(secondCrossCertificate.getCertificateToken().isSignedBy(secondCrossCertificateIssuer.getCertificateToken()));
        assertFalse(secondCrossCertificate.getCertificateToken().isSignedBy(firstCrossCertificateIssuer.getCertificateToken()));
        assertTrue(thirdCrossCertificate.getCertificateToken().isSignedBy(thirdCrossCertificateIssuer.getCertificateToken()));
        assertTrue(secondCrossCertificate.getCertificateToken().isSignedBy(thirdCrossCertificateIssuer.getCertificateToken()));
        assertTrue(thirdCrossCertificate.getCertificateToken().isSignedBy(secondCrossCertificateIssuer.getCertificateToken()));

        JAXBCertEntity crossedCa = repository.getCertEntityBySerialNumberAndParentSubject(2200L, "cc-root-ca");
        assertTrue(crossedCa.getCertificateToken().isSignedBy(firstCrossCertificate.getCertificateToken()));
        assertTrue(crossedCa.getCertificateToken().isSignedBy(secondCrossCertificate.getCertificateToken()));
        assertTrue(crossedCa.getCertificateToken().isSignedBy(thirdCrossCertificate.getCertificateToken()));
    }

    @Test
    void ed25519Test() {
        JAXBCertEntity goodUser = repository.getCertEntityBySubject("Ed25519-good-user");
        assertEquals(1100, goodUser.getSerialNumber());
        assertEquals("Ed25519-good-user", goodUser.getSubject());

        assertEquals(EncryptionAlgorithm.EDDSA.getName(), goodUser.getPrivateKey().getAlgorithm());
        assertEquals(SignatureAlgorithm.ED25519.getJCEId(), goodUser.getCertificateToken().getPublicKey().getAlgorithm());

        JAXBCertEntity goodCa = repository.getCertEntityBySubject("Ed25519-good-ca");
        assertEquals(1002, goodCa.getSerialNumber());
        assertEquals("Ed25519-good-ca", goodCa.getSubject());

        assertEquals(EncryptionAlgorithm.EDDSA.getName(), goodCa.getPrivateKey().getAlgorithm());
        assertEquals(SignatureAlgorithm.ED25519.getJCEId(), goodCa.getCertificateToken().getPublicKey().getAlgorithm());

        assertTrue(goodUser.getCertificateToken().isSignedBy(goodCa.getCertificateToken()));
    }

    @Test
    void ed448Test() {
        JAXBCertEntity goodUser = repository.getCertEntityBySubject("Ed448-good-user");
        assertEquals(1100, goodUser.getSerialNumber());
        assertEquals("Ed448-good-user", goodUser.getSubject());

        assertEquals(EncryptionAlgorithm.EDDSA.getName(), goodUser.getPrivateKey().getAlgorithm());
        assertEquals(SignatureAlgorithm.ED448.getJCEId(), goodUser.getCertificateToken().getPublicKey().getAlgorithm());

        JAXBCertEntity goodCa = repository.getCertEntityBySubject("Ed448-good-ca");
        assertEquals(1002, goodCa.getSerialNumber());
        assertEquals("Ed448-good-ca", goodCa.getSubject());

        assertEquals(EncryptionAlgorithm.EDDSA.getName(), goodCa.getPrivateKey().getAlgorithm());
        assertEquals(SignatureAlgorithm.ED448.getJCEId(), goodCa.getCertificateToken().getPublicKey().getAlgorithm());

        assertTrue(goodUser.getCertificateToken().isSignedBy(goodCa.getCertificateToken()));
    }

    @Test
    void qcStatementsTest() {
        JAXBCertEntity johnDoe = repository.getCertEntityBySubject("John Doe");
        assertEquals(100111, johnDoe.getSerialNumber());
        assertEquals("John Doe", johnDoe.getSubject());

        assertEquals("Test Qualified Trust Service Provider 1 from ZZ",
                DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.O, johnDoe.getCertificateToken().getSubject()));
        assertEquals("ZZ",
                DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.C, johnDoe.getCertificateToken().getSubject()));

        CertificatePolicies certificatePolicies = CertificateExtensionsUtils.getCertificatePolicies(johnDoe.getCertificateToken());
        assertNotNull(certificatePolicies);
        assertEquals(1, certificatePolicies.getPolicyList().size());
        assertEquals("1.3.6.1.4.1.314159.1.2", certificatePolicies.getPolicyList().get(0).getOid());

        QcStatements qcStatements = CertificateExtensionsUtils.getQcStatements(johnDoe.getCertificateToken());
        assertNotNull(qcStatements);
        assertTrue(qcStatements.isQcCompliance());
        assertTrue(qcStatements.isQcQSCD());

        assertEquals(1, qcStatements.getQcTypes().size());
        assertEquals(QCTypeEnum.QCT_ESIGN, qcStatements.getQcTypes().get(0));

        assertEquals(1, qcStatements.getQcLegislationCountryCodes().size());
        assertEquals("ZZ", qcStatements.getQcLegislationCountryCodes().get(0));

        JAXBCertEntity aliceDoe = repository.getCertEntityBySubject("Alice Doe");
        assertEquals(100114, aliceDoe.getSerialNumber());
        assertEquals("Alice Doe", aliceDoe.getSubject());

        assertEquals("Test Qualified Trust Service Provider 1 from ZZ",
                DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.O, aliceDoe.getCertificateToken().getSubject()));
        assertEquals("ZZ",
                DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.C, aliceDoe.getCertificateToken().getSubject()));

        certificatePolicies = CertificateExtensionsUtils.getCertificatePolicies(aliceDoe.getCertificateToken());
        assertNotNull(certificatePolicies);
        assertEquals(1, certificatePolicies.getPolicyList().size());
        assertEquals("1.3.6.1.4.1.314159.1.2", certificatePolicies.getPolicyList().get(0).getOid());

        qcStatements = CertificateExtensionsUtils.getQcStatements(aliceDoe.getCertificateToken());
        assertNotNull(qcStatements);
        assertFalse(qcStatements.isQcCompliance());
        assertFalse(qcStatements.isQcQSCD());

        assertEquals(1, qcStatements.getQcTypes().size());
        assertEquals(QCTypeEnum.QCT_ESIGN, qcStatements.getQcTypes().get(0));

        assertEquals(1, qcStatements.getQcLegislationCountryCodes().size());
        assertEquals("ZZ", qcStatements.getQcLegislationCountryCodes().get(0));

        JAXBCertEntity nonQualified = repository.getCertEntityBySubject("Test-Non-Qualified-TSA-from-ZZ");
        assertEquals(100140, nonQualified.getSerialNumber());
        assertEquals("Test-Non-Qualified-TSA-from-ZZ", nonQualified.getSubject());

        assertEquals("Test Non Qualified Trust Service Provider 1 from ZZ",
                DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.O, nonQualified.getCertificateToken().getSubject()));
        assertEquals("ZZ",
                DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.C, nonQualified.getCertificateToken().getSubject()));

        certificatePolicies = CertificateExtensionsUtils.getCertificatePolicies(nonQualified.getCertificateToken());
        assertNull(certificatePolicies);

        qcStatements = CertificateExtensionsUtils.getQcStatements(nonQualified.getCertificateToken());
        assertNull(qcStatements);
    }

}
