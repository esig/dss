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
package eu.europa.esig.dss.pki.jaxb.revocation.ocsp;

import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.exception.PKIException;
import eu.europa.esig.dss.pki.jaxb.AbstractTestJaxbPKI;
import eu.europa.esig.dss.pki.x509.revocation.ocsp.PKIOCSPSource;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.ocsp.RespID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JaxbPKIOCSPSourceTest extends AbstractTestJaxbPKI {

    private static CertificateToken goodUser;
    private static CertificateToken goodCa;
    private static CertificateToken ocspResponder;
    private static CertificateToken rootToken;
    private static CertificateToken goodUserOCSPWithReqCertId;
    private static CertificateToken ed25519goodUser;
    private static CertificateToken ed25519goodCa;
    private static CertificateToken revokedCa;
    private static CertificateToken revokedUser;

    @BeforeAll
    public static void init() {
        goodUser = repository.getCertEntityBySubject("good-user").getCertificateToken();
        goodCa = repository.getCertEntityBySubject("good-ca").getCertificateToken();
        ocspResponder = repository.getCertEntityBySubject("ocsp-responder").getCertificateToken();
        rootToken = repository.getCertEntityBySubject("root-ca").getCertificateToken();
        goodUserOCSPWithReqCertId = repository.getCertEntityBySubject("good-user-ocsp-certid-digest").getCertificateToken();
        ed25519goodUser = repository.getCertEntityBySubject("Ed25519-good-user").getCertificateToken();
        ed25519goodCa = repository.getCertEntityBySubject("Ed25519-good-ca").getCertificateToken();
        revokedCa = repository.getCertEntityBySubject("revoked-ca").getCertificateToken();
        revokedUser = repository.getCertEntityBySubject("revoked-user").getCertificateToken();
    }

    @Test
    public void testOCSP() {
        PKIOCSPSource ocspSource = new PKIOCSPSource(repository);
        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
        assertEquals(SignatureAlgorithm.RSA_SHA256, ocspToken.getSignatureAlgorithm());
        assertEquals(goodCa, ocspToken.getIssuerCertificateToken());
        assertEquals(CertificateStatus.GOOD, ocspToken.getStatus());
    }

    @Test
    public void testOCSPWithProducedAtTime() {
        PKIOCSPSource ocspSource = new PKIOCSPSource(repository);

        Date producedAt = DSSUtils.getUtcDate(2023, 6, 6);
        ocspSource.setProducedAtTime(producedAt);

        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, rootToken);
        assertNotNull(ocspToken);
        assertEquals(producedAt, ocspToken.getProductionDate());
        assertEquals(producedAt, ocspToken.getThisUpdate());
    }

    @Test
    public void testOCSPWithThisUpdate() {
        PKIOCSPSource ocspSource = new PKIOCSPSource(repository);

        Date thisUpdate = DSSUtils.getUtcDate(2023, 6, 6);
        ocspSource.setThisUpdate(thisUpdate);

        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, rootToken);
        assertNotNull(ocspToken);
        assertNotEquals(thisUpdate, ocspToken.getProductionDate());
        assertEquals(thisUpdate, ocspToken.getThisUpdate());
    }

    @Test
    public void testOCSPWithThisUpdateAndProducedAtTime() {
        PKIOCSPSource ocspSource = new PKIOCSPSource(repository);

        Date thisUpdate = DSSUtils.getUtcDate(2023, 6, 1);
        ocspSource.setThisUpdate(thisUpdate);
        Date producedAt = DSSUtils.getUtcDate(2023, 6, 6);
        ocspSource.setProducedAtTime(producedAt);

        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, rootToken);
        assertNotNull(ocspToken);
        assertEquals(producedAt, ocspToken.getProductionDate());
        assertEquals(thisUpdate, ocspToken.getThisUpdate());
    }

    @Test
    public void testOCSPWithNextUpdate() {
        PKIOCSPSource ocspSource = new PKIOCSPSource(repository);

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_WEEK, 7);
        calendar.set(Calendar.MILLISECOND, 0);
        Date nextUpdate = calendar.getTime();
        ocspSource.setNextUpdate(nextUpdate);

        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, rootToken);
        assertNotNull(ocspToken);
        assertEquals(nextUpdate, ocspToken.getNextUpdate());
    }

    @Test
    public void testOCSPWithPss() {
        PKIOCSPSource ocspSource = new PKIOCSPSource(repository);
        ocspSource.setMaskGenerationFunction(MaskGenerationFunction.MGF1);
        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, rootToken);
        assertNotNull(ocspToken);
        assertEquals(SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1, ocspToken.getSignatureAlgorithm());
    }

    @Test
    public void testOCSPRevoked() {
        PKIOCSPSource ocspSource = new PKIOCSPSource(repository);
        OCSPToken ocspToken = ocspSource.getRevocationToken(revokedUser, revokedCa);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
        assertEquals(CertificateStatus.REVOKED, ocspToken.getStatus());
    }

    @Test
    public void testOCSPEd25519() {
        PKIOCSPSource ocspSource = new PKIOCSPSource(repository);
        ocspSource.setDigestAlgorithm(DigestAlgorithm.SHA512);
        OCSPToken ocspToken = ocspSource.getRevocationToken(ed25519goodUser, ed25519goodCa);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
        assertEquals(SignatureAlgorithm.ED25519, ocspToken.getSignatureAlgorithm());
    }

    @Test
    public void testOCSPWithDelegatedIssuer() {
        PKIOCSPSource ocspSource = new PKIOCSPSource(repository, repository.getByCertificateToken(ocspResponder));
        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
        assertEquals(ocspResponder, ocspToken.getIssuerCertificateToken());
    }

    @Test
    public void testOCSPWithResponderIdByKey() {
        PKIOCSPSource ocspSource = new PKIOCSPSource(repository);
        ocspSource.setResponderIdByKey(true);
        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());

        RespID respId = ocspToken.getBasicOCSPResp().getResponderId();
        assertNotNull(respId);
        ResponderID responderID = respId.toASN1Primitive();

        assertNotNull(responderID.getKeyHash());
        assertTrue(DSSASN1Utils.isSkiEqual(responderID.getKeyHash(), goodCa));

        assertNull(responderID.getName());
    }

    @Test
    public void testOCSPWithResponderIdByName() throws IOException {
        PKIOCSPSource ocspSource = new PKIOCSPSource(repository);
        ocspSource.setResponderIdByKey(false);
        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());

        RespID respId = ocspToken.getBasicOCSPResp().getResponderId();
        assertNotNull(respId);
        ResponderID responderID = respId.toASN1Primitive();

        assertNull(responderID.getKeyHash());

        X500Name name = responderID.getName();
        assertNotNull(name);
        assertArrayEquals(DSSASN1Utils.getX509CertificateHolder(goodCa).getSubject().getEncoded(), name.getEncoded());
    }

    @Test
    public void customCertIDDigestAlgorithmTest() {
        PKIOCSPSource ocspSource = new PKIOCSPSource(repository);
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

    @Test
    public void testWrongIssuer() {
        PKIOCSPSource ocspSource = new PKIOCSPSource(repository);

        CertificateToken caToken = DSSUtils.loadCertificateFromBase64EncodedString("MIIDjjCCAnagAwIBAgIIKv++n6Lw6YcwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMDcxMDA0MTAwMDAwWhcNMjExMjE1MDgwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZzQh6S/3UPi790hqc/7bIYLS2X+an7mEoj39WN4IzGMhwWLQdC1i22bi+n9fzGhYJdld61IgDMqFNAn68KNaJ6x+HK92AQZw6nUHMXU5WfIp8MXW+2QbyM69odRr2nlL/zGsvU+40OHjPIltfsjFPekx40HopQcSZYtF3CiInaYNKJIT/e1wEYNm7hLHADBGXvmAYrXR5i3FVr/mZkIV/4L+HXmymvb82fqgxG0YjFnaKVn6w/Fa7yYd/vw2uaItgscf1YHewApDgglVrH1Tdjuk+bqv5WRi5j2Qsj1Yr6tSPwiRuhFA0m2kHwOI8w7QUmecFLTqG4flVSOmlGhHUCAwEAAaOBuzCBuDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGBWA4CQEBMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUhYrr9MW7vg5ZA5Te1oABFeMQnDkwDQYJKoZIhvcNAQEFBQADggEBAFHYhd27V2/MoGy1oyCcUwnzSgEMdL8rs5qauhjyC4isHLMzr87lEwEnkoRYmhC598wUkmt0FoqW6FHvv/pKJaeJtmMrXZRY0c8RcrYeuTlBFk0pvDVTC9rejg7NqZV3JcqUWumyaa7YwBO+mPyWnIR/VRPmPIfjvCCkpDZoa01gZhz5v6yAlGYuuUGK02XThIAC71AdXkbc98m6tTR8KvPG2F9fVJ3bTc0R5/0UAoNmXsimABKgX77OFP67H6dh96tK8QYUn8pJQsKpvO2FsauBQeYNxUJpU4c5nUwfAA4+Bw11V0SoU7Q2dmSZ3G7rPUZuFF1eR1ONeE3gJ7uOhXY=");

        Exception exception = assertThrows(PKIException.class, () -> ocspSource.getRevocationToken(goodUser, caToken));
        assertEquals("CertEntity for certificate token with " +
                "Id 'C-9F9744463BE13714754E1A3BECF98C08CC205E4AB32028F4E2830C4A1B2775B8' not found in the repository! " +
                "Provide a valid issuer or use #setOcspResponder method to set a custom OCSP responder.", exception.getMessage());
    }

    @Test
    public void setNullRepositoryTest() {
        Exception exception = assertThrows(NullPointerException.class, () -> new PKIOCSPSource(null));
        assertEquals("Certificate repository shall be provided!", exception.getMessage());
    }

    @Test
    public void setNullCertificateTokenTest() {
        PKIOCSPSource ocspSource = new PKIOCSPSource(repository);
        Exception exception = assertThrows(NullPointerException.class, () -> ocspSource.getRevocationToken(null, goodCa));
        assertEquals("Certificate cannot be null!", exception.getMessage());
    }

    @Test
    public void setNullIssuerCertificateTokenTest() {
        PKIOCSPSource ocspSource = new PKIOCSPSource(repository);
        Exception exception = assertThrows(NullPointerException.class, () -> ocspSource.getRevocationToken(goodUser, null));
        assertEquals("The issuer of the certificate to be verified cannot be null!", exception.getMessage());
    }

}
