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
package eu.europa.esig.dss.pki.jaxb.revocation.crl;

import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureValidity;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.exception.PKIException;
import eu.europa.esig.dss.pki.jaxb.AbstractTestJaxbPKI;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.x509.revocation.crl.PKICRLSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JaxbPKICRLSourceTest extends AbstractTestJaxbPKI {

    private static CertificateToken goodUser;
    private static CertificateToken goodCa;
    private static CertificateToken rootCa;

    private static CertificateToken ed25519goodUser;
    private static CertificateToken ed25519goodCa;
    private static CertificateToken ed25519RootCa;
    private static CertificateToken revokedCa;
    private static CertificateToken sha3GoodCa;
    private static CertificateToken sha3RootCa;

    @BeforeAll
    static void init() {
        goodUser = repository.getCertEntityBySubject("good-user").getCertificateToken();
        goodCa = repository.getCertEntityBySubject("good-ca").getCertificateToken();
        rootCa = repository.getCertEntityBySubject("root-ca").getCertificateToken();
        revokedCa = repository.getCertEntityBySubject("revoked-ca").getCertificateToken();
        sha3GoodCa = repository.getCertEntityBySubject("sha3-good-ca").getCertificateToken();
        sha3RootCa = repository.getCertEntityBySubject("sha3-root-ca").getCertificateToken();

        ed25519goodUser = repository.getCertEntityBySubject("Ed25519-good-user").getCertificateToken();
        ed25519goodCa = repository.getCertEntityBySubject("Ed25519-good-ca").getCertificateToken();
        ed25519RootCa = repository.getCertEntityBySubject("Ed25519-root-ca").getCertificateToken();
    }

    @Test
    void getRevocationTokenTest() {
        PKICRLSource pkiCRLSource = initPkiCRLSource();
        CRLToken revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
        assertEquals(rootCa, revocationToken.getIssuerCertificateToken());
        assertEquals(SignatureAlgorithm.RSA_SHA512, revocationToken.getSignatureAlgorithm());
        assertEquals(CertificateStatus.GOOD, revocationToken.getStatus());
    }

    @Test
    void getRevocationTokenSha256Test() {
        PKICRLSource pkiCRLSource = initPkiCRLSource();
        pkiCRLSource.setDigestAlgorithm(DigestAlgorithm.SHA256);
        CRLToken revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
        assertEquals(rootCa, revocationToken.getIssuerCertificateToken());
        assertEquals(SignatureAlgorithm.RSA_SHA256, revocationToken.getSignatureAlgorithm());
        assertEquals(CertificateStatus.GOOD, revocationToken.getStatus());
    }

    @Test
    void getRevocationTokenWithCertEntityTest() {
        PKICRLSource pkiCRLSource = initPkiCRLSource(repository.getByCertificateToken(rootCa));
        CRLToken revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
        assertEquals(rootCa, revocationToken.getIssuerCertificateToken());
    }

    @Test
    void setCRLIssuerTest() {
        PKICRLSource pkiCRLSource = initPkiCRLSource();
        pkiCRLSource.setCrlIssuer(repository.getByCertificateToken(rootCa));
        CRLToken revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
        assertEquals(rootCa, revocationToken.getIssuerCertificateToken());
    }

    @Test
    void getRevokedTest() {
        PKICRLSource pkiCRLSource = initPkiCRLSource();
        CRLToken revocationToken = pkiCRLSource.getRevocationToken(revokedCa, rootCa);
        assertNotNull(revocationToken);
        assertEquals(CertificateStatus.REVOKED, revocationToken.getStatus());
    }

    @Test
    void getRevocationTokenSha3() {
        PKICRLSource pkiCRLSource = initPkiCRLSource();
        pkiCRLSource.setDigestAlgorithm(DigestAlgorithm.SHA3_256);
        CRLToken revocationToken = pkiCRLSource.getRevocationToken(sha3GoodCa, sha3RootCa);
        assertNotNull(revocationToken);
        assertEquals(SignatureAlgorithm.RSA_SHA3_256, revocationToken.getSignatureAlgorithm());
    }

    @Test
    void getRevocationTokenWithMaskGenerationFunction() {
        PKICRLSource pkiCRLSource = initPkiCRLSource();
        pkiCRLSource.setEncryptionAlgorithm(EncryptionAlgorithm.RSASSA_PSS);
        CRLToken revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
        assertEquals(SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, revocationToken.getSignatureAlgorithm());
    }

    @Test
    void getRevocationTokenEd25519Test() {
        PKICRLSource pkiCRLSource = initPkiCRLSource();
        pkiCRLSource.setDigestAlgorithm(DigestAlgorithm.SHA512);

        CRLToken revocationToken = pkiCRLSource.getRevocationToken(ed25519goodUser, ed25519goodCa);

        assertNull(revocationToken);

        pkiCRLSource = initPkiCRLSource();
        pkiCRLSource.setDigestAlgorithm(DigestAlgorithm.SHA512);

        revocationToken = pkiCRLSource.getRevocationToken(ed25519goodCa, ed25519RootCa);
        pkiCRLSource.setDigestAlgorithm(DigestAlgorithm.SHA512);

        assertNotNull(revocationToken);
        assertTrue(revocationToken.isSignatureIntact());
        assertTrue(revocationToken.isValid());
        assertEquals(SignatureAlgorithm.ED25519, revocationToken.getSignatureAlgorithm());
        assertEquals(SignatureValidity.VALID, revocationToken.getSignatureValidity());
    }

    @Test
    void getRevocationThisUpdateTest() {
        PKICRLSource pkiCRLSource = initPkiCRLSource();

        Date thisUpdate = DSSUtils.getUtcDate(2023, 6, 6);
        pkiCRLSource.setThisUpdate(thisUpdate);

        CRLToken revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
        assertEquals(thisUpdate, revocationToken.getThisUpdate());

        pkiCRLSource.setThisUpdate(null);

        revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
        assertNotNull(revocationToken.getThisUpdate());
        assertNotEquals(thisUpdate, revocationToken.getThisUpdate());
    }

    @Test
    void getRevocationNextUpdateTest() {
        PKICRLSource pkiCRLSource = initPkiCRLSource();

        Date nextUpdate = DSSUtils.getUtcDate(2023, 6, 6);
        pkiCRLSource.setNextUpdate(nextUpdate);

        CRLToken revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
        assertEquals(nextUpdate, revocationToken.getNextUpdate());

        pkiCRLSource.setNextUpdate(null);

        revocationToken = pkiCRLSource.getRevocationToken(goodCa, rootCa);
        assertNotNull(revocationToken);
        assertNull(revocationToken.getNextUpdate());
    }

    @Test
    void testWrongIssuer() {
        PKICRLSource crlSource = initPkiCRLSource();

        CertificateToken caToken = DSSUtils.loadCertificateFromBase64EncodedString("MIIDjjCCAnagAwIBAgIIKv++n6Lw6YcwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMDcxMDA0MTAwMDAwWhcNMjExMjE1MDgwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZzQh6S/3UPi790hqc/7bIYLS2X+an7mEoj39WN4IzGMhwWLQdC1i22bi+n9fzGhYJdld61IgDMqFNAn68KNaJ6x+HK92AQZw6nUHMXU5WfIp8MXW+2QbyM69odRr2nlL/zGsvU+40OHjPIltfsjFPekx40HopQcSZYtF3CiInaYNKJIT/e1wEYNm7hLHADBGXvmAYrXR5i3FVr/mZkIV/4L+HXmymvb82fqgxG0YjFnaKVn6w/Fa7yYd/vw2uaItgscf1YHewApDgglVrH1Tdjuk+bqv5WRi5j2Qsj1Yr6tSPwiRuhFA0m2kHwOI8w7QUmecFLTqG4flVSOmlGhHUCAwEAAaOBuzCBuDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGBWA4CQEBMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUhYrr9MW7vg5ZA5Te1oABFeMQnDkwDQYJKoZIhvcNAQEFBQADggEBAFHYhd27V2/MoGy1oyCcUwnzSgEMdL8rs5qauhjyC4isHLMzr87lEwEnkoRYmhC598wUkmt0FoqW6FHvv/pKJaeJtmMrXZRY0c8RcrYeuTlBFk0pvDVTC9rejg7NqZV3JcqUWumyaa7YwBO+mPyWnIR/VRPmPIfjvCCkpDZoa01gZhz5v6yAlGYuuUGK02XThIAC71AdXkbc98m6tTR8KvPG2F9fVJ3bTc0R5/0UAoNmXsimABKgX77OFP67H6dh96tK8QYUn8pJQsKpvO2FsauBQeYNxUJpU4c5nUwfAA4+Bw11V0SoU7Q2dmSZ3G7rPUZuFF1eR1ONeE3gJ7uOhXY=");

        Exception exception = assertThrows(PKIException.class, () -> crlSource.getRevocationToken(goodCa, caToken));
        assertEquals("CertEntity for certificate token with " +
                "Id 'C-9F9744463BE13714754E1A3BECF98C08CC205E4AB32028F4E2830C4A1B2775B8' not found in the repository! " +
                "Provide a valid issuer or use #setCrlIssuer method to set a custom issuer.", exception.getMessage());
    }

    @Test
    void setNullRepositoryTest() {
        Exception exception = assertThrows(NullPointerException.class, () -> new PKICRLSource(null));
        assertEquals("Certificate repository shall be provided!", exception.getMessage());
    }

    @Test
    void setNullCertificateTokenTest() {
        PKICRLSource crlSource = new PKICRLSource(repository);
        Exception exception = assertThrows(NullPointerException.class, () -> crlSource.getRevocationToken(null, goodCa));
        assertEquals("Certificate cannot be null!", exception.getMessage());
    }

    @Test
    void setNullIssuerCertificateTokenTest() {
        PKICRLSource crlSource = new PKICRLSource(repository);
        Exception exception = assertThrows(NullPointerException.class, () -> crlSource.getRevocationToken(goodUser, null));
        assertEquals("The issuer of the certificate to be verified cannot be null!", exception.getMessage());
    }

    private static PKICRLSource initPkiCRLSource() {
        return initPkiCRLSource(null);
    }

    private static PKICRLSource initPkiCRLSource(CertEntity crlIssuer) {
        PKICRLSource pkiCRLSource = crlIssuer != null ? new PKICRLSource(repository, crlIssuer) : new PKICRLSource(repository);

        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MONTH, 6);
        Date nextUpdate = cal.getTime();
        pkiCRLSource.setNextUpdate(nextUpdate);
        pkiCRLSource.setThisUpdate(new Date());
        return pkiCRLSource;
    }

}
