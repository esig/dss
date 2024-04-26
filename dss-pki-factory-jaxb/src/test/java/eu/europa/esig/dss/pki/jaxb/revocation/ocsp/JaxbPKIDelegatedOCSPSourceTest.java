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
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.exception.PKIException;
import eu.europa.esig.dss.pki.jaxb.AbstractTestJaxbPKI;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.x509.revocation.ocsp.PKIDelegatedOCSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class JaxbPKIDelegatedOCSPSourceTest extends AbstractTestJaxbPKI {

    private static CertificateToken goodUser;
    private static CertificateToken goodCa;
    private static CertificateToken ocspResponder;

    @BeforeAll
    public static void init() {
        goodUser = repository.getCertEntityBySubject("good-user").getCertificateToken();
        goodCa = repository.getCertEntityBySubject("good-ca").getCertificateToken();
        ocspResponder = repository.getCertEntityBySubject("ocsp-responder").getCertificateToken();
    }

    @Test
    public void testDelegate() {
        PKIDelegatedOCSPSource ocspSource = new PKIDelegatedOCSPSource(repository);

        Map<CertEntity, CertEntity> ocspResponders = new HashMap<>();
        ocspResponders.put(repository.getByCertificateToken(goodCa), repository.getByCertificateToken(ocspResponder));
        ocspSource.setOcspResponders(ocspResponders);

        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
        assertEquals(SignatureAlgorithm.RSA_SHA512, ocspToken.getSignatureAlgorithm());
        assertEquals(ocspResponder, ocspToken.getIssuerCertificateToken());
        assertEquals(CertificateStatus.GOOD, ocspToken.getStatus());
    }

    @Test
    public void testDelegateSha256() {
        PKIDelegatedOCSPSource ocspSource = new PKIDelegatedOCSPSource(repository);
        ocspSource.setDigestAlgorithm(DigestAlgorithm.SHA256);

        Map<CertEntity, CertEntity> ocspResponders = new HashMap<>();
        ocspResponders.put(repository.getByCertificateToken(goodCa), repository.getByCertificateToken(ocspResponder));
        ocspSource.setOcspResponders(ocspResponders);

        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
        assertEquals(SignatureAlgorithm.RSA_SHA256, ocspToken.getSignatureAlgorithm());
        assertEquals(ocspResponder, ocspToken.getIssuerCertificateToken());
        assertEquals(CertificateStatus.GOOD, ocspToken.getStatus());
    }

    @Test
    public void testNoDelegation() {
        PKIDelegatedOCSPSource ocspSource = new PKIDelegatedOCSPSource(repository);

        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
        assertEquals(SignatureAlgorithm.RSA_SHA512, ocspToken.getSignatureAlgorithm());
        assertEquals(goodCa, ocspToken.getIssuerCertificateToken());
        assertEquals(CertificateStatus.GOOD, ocspToken.getStatus());
    }

    @Test
    public void testNullMap() {
        PKIDelegatedOCSPSource ocspSource = new PKIDelegatedOCSPSource(repository);
        ocspSource.setOcspResponders(null);

        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
        assertEquals(SignatureAlgorithm.RSA_SHA512, ocspToken.getSignatureAlgorithm());
        assertEquals(goodCa, ocspToken.getIssuerCertificateToken());
        assertEquals(CertificateStatus.GOOD, ocspToken.getStatus());
    }

    @Test
    public void testEmptyMap() {
        PKIDelegatedOCSPSource ocspSource = new PKIDelegatedOCSPSource(repository);
        ocspSource.setOcspResponders(new HashMap<>());

        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
        assertEquals(SignatureAlgorithm.RSA_SHA512, ocspToken.getSignatureAlgorithm());
        assertEquals(goodCa, ocspToken.getIssuerCertificateToken());
        assertEquals(CertificateStatus.GOOD, ocspToken.getStatus());
    }

    @Test
    public void testNullValueMap() {
        PKIDelegatedOCSPSource ocspSource = new PKIDelegatedOCSPSource(repository);

        Map<CertEntity, CertEntity> ocspResponders = new HashMap<>();
        ocspResponders.put(repository.getByCertificateToken(goodCa), null);
        ocspSource.setOcspResponders(ocspResponders);

        OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
        assertNotNull(ocspToken);
        assertNotNull(ocspToken.getBasicOCSPResp());
        assertEquals(SignatureAlgorithm.RSA_SHA512, ocspToken.getSignatureAlgorithm());
        assertEquals(goodCa, ocspToken.getIssuerCertificateToken());
        assertEquals(CertificateStatus.GOOD, ocspToken.getStatus());
    }

    @Test
    public void testSetOcspResponder() {
        PKIDelegatedOCSPSource ocspSource = new PKIDelegatedOCSPSource(repository);
        Exception exception = assertThrows(UnsupportedOperationException.class,
                () -> ocspSource.setOcspResponder(repository.getByCertificateToken(ocspResponder)));
        assertEquals("Method #setOcspResponder is not supported within PKIDelegatedOCSPSource class. " +
                "Use #setOcspResponders method instead.", exception.getMessage());
    }

    @Test
    public void testWrongIssuer() {
        PKIDelegatedOCSPSource ocspSource = new PKIDelegatedOCSPSource(repository);

        CertificateToken caToken = DSSUtils.loadCertificateFromBase64EncodedString("MIIDjjCCAnagAwIBAgIIKv++n6Lw6YcwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMDcxMDA0MTAwMDAwWhcNMjExMjE1MDgwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZzQh6S/3UPi790hqc/7bIYLS2X+an7mEoj39WN4IzGMhwWLQdC1i22bi+n9fzGhYJdld61IgDMqFNAn68KNaJ6x+HK92AQZw6nUHMXU5WfIp8MXW+2QbyM69odRr2nlL/zGsvU+40OHjPIltfsjFPekx40HopQcSZYtF3CiInaYNKJIT/e1wEYNm7hLHADBGXvmAYrXR5i3FVr/mZkIV/4L+HXmymvb82fqgxG0YjFnaKVn6w/Fa7yYd/vw2uaItgscf1YHewApDgglVrH1Tdjuk+bqv5WRi5j2Qsj1Yr6tSPwiRuhFA0m2kHwOI8w7QUmecFLTqG4flVSOmlGhHUCAwEAAaOBuzCBuDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGBWA4CQEBMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUhYrr9MW7vg5ZA5Te1oABFeMQnDkwDQYJKoZIhvcNAQEFBQADggEBAFHYhd27V2/MoGy1oyCcUwnzSgEMdL8rs5qauhjyC4isHLMzr87lEwEnkoRYmhC598wUkmt0FoqW6FHvv/pKJaeJtmMrXZRY0c8RcrYeuTlBFk0pvDVTC9rejg7NqZV3JcqUWumyaa7YwBO+mPyWnIR/VRPmPIfjvCCkpDZoa01gZhz5v6yAlGYuuUGK02XThIAC71AdXkbc98m6tTR8KvPG2F9fVJ3bTc0R5/0UAoNmXsimABKgX77OFP67H6dh96tK8QYUn8pJQsKpvO2FsauBQeYNxUJpU4c5nUwfAA4+Bw11V0SoU7Q2dmSZ3G7rPUZuFF1eR1ONeE3gJ7uOhXY=");

        Exception exception = assertThrows(PKIException.class, () -> ocspSource.getRevocationToken(goodUser, caToken));
        assertEquals("CertEntity for certificate token with " +
                "Id 'C-9F9744463BE13714754E1A3BECF98C08CC205E4AB32028F4E2830C4A1B2775B8' not found in the repository! " +
                "Provide a valid issuer.", exception.getMessage());
    }

}
