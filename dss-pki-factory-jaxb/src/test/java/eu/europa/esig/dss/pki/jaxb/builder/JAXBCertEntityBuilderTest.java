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
package eu.europa.esig.dss.pki.jaxb.builder;

import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.jaxb.AbstractTestJaxbPKI;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntity;
import eu.europa.esig.dss.pki.x509.revocation.ocsp.PKIOCSPSource;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JAXBCertEntityBuilderTest extends AbstractTestJaxbPKI {

    @Test
    void test() throws Exception {
        JAXBCertEntity goodCa = repository.getCertEntityBySubject("good-ca");

        X500Name x500Name = new X500NameBuilder()
                .commonName("new-good-user").organisation("Nowina Solutions").country("LU")
                .build();

        KeyPair keyPair = new KeyPairBuilder(EncryptionAlgorithm.RSA, 2048).build();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(Calendar.MILLISECOND, 0);
        calendar.add(Calendar.MONTH, -12);
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.MONTH, 24);
        Date notAfter = calendar.getTime();

        CertificateToken certificateToken = new X509CertificateBuilder()
                .subject(x500Name, BigInteger.valueOf(101), keyPair.getPublic())
                .issuer(goodCa.getCertificateToken(), goodCa.getPrivateKey(), SignatureAlgorithm.RSA_SHA256)
                .notBefore(notBefore).notAfter(notAfter)
                .ocsp("http://dss.nowina.lu/pki/ocsp")
                .build();

        JAXBCertEntity certEntity = new JAXBCertEntityBuilder()
                .setCertificateToken(certificateToken).setIssuer(goodCa).setPrivateKey(keyPair.getPrivate())
                .build();
        assertNotNull(certEntity);

        repository.save(certEntity);

        JAXBCertEntity newGoodUser = repository.getCertEntityBySubject("new-good-user");
        assertNotNull(newGoodUser);

        assertEquals(101, newGoodUser.getSerialNumber());
        assertEquals("new-good-user", newGoodUser.getSubject());

        CertificateToken newGoodUserCertificate = newGoodUser.getCertificateToken();
        assertEquals(notBefore, newGoodUserCertificate.getNotBefore());
        assertEquals(notAfter, newGoodUserCertificate.getNotAfter());

        assertEquals("Nowina Solutions",
                DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.O, newGoodUserCertificate.getSubject()));
        assertEquals("LU",
                DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.C, newGoodUserCertificate.getSubject()));

        assertEquals(EncryptionAlgorithm.RSA.getName(), newGoodUserCertificate.getPublicKey().getAlgorithm());
        assertTrue(newGoodUserCertificate.getPublicKey() instanceof RSAPublicKey);
        assertEquals(2048, ((RSAPublicKey) newGoodUserCertificate.getPublicKey()).getModulus().bitLength());

        List<CertificateToken> certificateChain = newGoodUser.getCertificateChain();
        assertEquals(3, certificateChain.size());

        PKIOCSPSource ocspSource = new PKIOCSPSource(repository);
        OCSPToken ocspToken = ocspSource.getRevocationToken(newGoodUserCertificate, goodCa.getCertificateToken());
        assertNotNull(ocspToken);
        assertEquals(CertificateStatus.GOOD, ocspToken.getStatus());

        calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(Calendar.MILLISECOND, 0);
        Date revocationDate = calendar.getTime();

        newGoodUser.setRevocationDate(revocationDate);
        newGoodUser.setRevocationReason(RevocationReason.KEY_COMPROMISE);

        ocspToken = ocspSource.getRevocationToken(newGoodUserCertificate, goodCa.getCertificateToken());
        assertNotNull(ocspToken);
        assertEquals(CertificateStatus.REVOKED, ocspToken.getStatus());
        assertEquals(revocationDate, ocspToken.getRevocationDate());
        assertEquals(RevocationReason.KEY_COMPROMISE, ocspToken.getReason());
    }

}
