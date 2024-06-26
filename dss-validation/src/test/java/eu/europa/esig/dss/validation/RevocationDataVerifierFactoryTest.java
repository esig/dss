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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.AlgoExpirationDate;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.ListAlgo;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.TimeConstraint;
import eu.europa.esig.dss.policy.jaxb.TimeUnit;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.spi.validation.RevocationDataVerifier;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RevocationDataVerifierFactoryTest {

    @Test
    public void digestAlgorithmWithValidationPolicyTest() throws Exception {
        String certB64 = "MIIFQDCCBCigAwIBAgIOGCB2t4Cg4gEAAQAOEN4wDQYJKoZIhvcNAQELBQAwbTELMAkGA1UEBhMCTFQxEjAQBgNVBGETCTE4ODc3ODMxNTE2MDQGA1UEChMtQXNtZW5zIGRva3VtZW50dSBpc3Jhc3ltbyBjZW50cmFzIHByaWUgTFIgVlJNMRIwEAYDVQQDEwlBRElDIENBLUEwHhcNMTkwMTE1MDc1MDUwWhcNMjIwMTE0MDc1MDUwWjBlMQswCQYDVQQGEwJMVDEaMBgGA1UEAwwRQURPTUFTIEJJUsWgVFVOQVMxEzARBgNVBAQMCkJJUsWgVFVOQVMxDzANBgNVBCoTBkFET01BUzEUMBIGA1UEBRMLMzgwMDMxMzA2OTMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpBBVaIBn1jxl44uuvkJWkW5F3rtoUsmAkMJPlPyzQOg87h07uYOIJk4YDIpvujDaL3y3RAy7ARFWpY31zn0b0TnMkDyuf5JYtro6ZpR3v/wijVUNYyGZYpbc42WVNVp/AYuE6IJ7ecE1dMMJDHVkJAmoH2wnT+Lnqp71n51luYc5v0VP+OFmPqPzuSbiwXewOg8PHARkv9l8d0FnoUmKg5xpm+jbjCFsOC77hkwjUDQxu9Yv7p+T1X7+se46GDOm287i2iW66bZYu4qy6ycrznNuwWLtU1i5Z7ypoNGJ++IRn4wP80CvwzUo5TNcLD8Ql3PaDs8GPKXfpBz2zd4MBAgMBAAGjggHkMIIB4DBLBgNVHQkERDBCMA8GCCsGAQUFBwkDMQMTAU0wHQYIKwYBBQUHCQExERgPMTk4MDAzMTMxMjAwMDBaMBAGCCsGAQUFBwkEMQQTAkxUMB0GA1UdDgQWBBSkKwML7BV258Cpil5bewoD6itogjAOBgNVHQ8BAf8EBAMCBsAwHwYDVR0jBBgwFoAUYpbcZMVf8JBEU79q1WAACu/0N7IweAYIKwYBBQUHAQEEbDBqMDQGCCsGAQUFBzABhihodHRwOi8vbnNjLnZybS5sdC9PQ1NQL29jc3ByZXNwb25kZXIubnNjMDIGCCsGAQUFBzAChiZodHRwOi8vbnNjLnZybS5sdC9haWEvQURJQ19DQS1BKDEpLmNydDAVBgNVHSUEDjAMBgorBgEEAYI3CgMMMEQGA1UdIAQ9MDswOQYLKwYBBAGChlUCAgIwKjAoBggrBgEFBQcCARYcaHR0cDovL25zYy52cm0ubHQvcmVwb3NpdG9yeTAdBgkrBgEEAYI3FQoEEDAOMAwGCisGAQQBgjcKAwwwSwYIKwYBBQUHAQMEPzA9MAgGBgQAjkYBATAIBgYEAI5GAQQwJwYGBACORgEFMB0wGxYVaHR0cDovL25zYy52cm0ubHQvcGRzEwJlbjANBgkqhkiG9w0BAQsFAAOCAQEAIHcOUDrDtW1cJVkCsKpdniYpBBoZfmwX0VIM+mTevRb/dCTMyHHp+DkfauWXEGUEkl+PoZb8r9hoYcBWYvbIXbSEPnoRX26BLXeNGKz4LxqoqoHRqDFSOr7+7uFkhIwalM5mjc9c/oOJZu5xTALH/TCSRD4TVp48/+UiII/JpC+700N8oNbPkJUoKBpfRFcD89WGlvywrGYyD1nPoSn+KF7lmxenl+KEJKE6q0UdzV9kbzkk7BlksiUL9U9D0c7emx6pRk1Mw7fqTVD/ETGqmKVR6lzIQcY/GLQ55W968FrovU6F7TP/7qW8ahYzdM09sEnoIeG5jet3mYVHPEyGMA==";
        String caCertB64 = "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";
        String ocspTokenB64 = "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";

        ExternalResourcesOCSPSource ocspSource = new ExternalResourcesOCSPSource(new InMemoryDocument(Utils.fromBase64(ocspTokenB64)));
        List<RevocationToken<OCSP>> revocationTokens = ocspSource.getRevocationTokens(DSSUtils.loadCertificateFromBase64EncodedString(certB64), DSSUtils.loadCertificateFromBase64EncodedString(caCertB64));
        assertEquals(1, revocationTokens.size());

        RevocationToken<OCSP> ocspToken = revocationTokens.iterator().next();

        ValidationPolicy validationPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        CryptographicConstraint cryptographic = validationPolicy.getCryptographic();
        cryptographic.setLevel(Level.IGNORE);

        RevocationDataVerifier revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertTrue(revocationDataVerifier.isAcceptable(ocspToken));

        validationPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        cryptographic = validationPolicy.getCryptographic();
        cryptographic.setLevel(Level.FAIL);

        ListAlgo acceptableDigestAlgo = cryptographic.getAcceptableDigestAlgo();
        acceptableDigestAlgo.getAlgos().clear();

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertFalse(revocationDataVerifier.isAcceptable(ocspToken)); // SHA-1

        AlgoExpirationDate algoExpirationDate = cryptographic.getAlgoExpirationDate();
        algoExpirationDate.setFormat("yyyy");

        Algo algo = new Algo();
        algo.setValue("SHA1");
        algo.setDate("2009");
        acceptableDigestAlgo.getAlgos().add(algo);
        algoExpirationDate.getAlgos().add(algo);

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertFalse(revocationDataVerifier.isAcceptable(ocspToken));

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(Calendar.YEAR, 2000);

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).setValidationTime(calendar.getTime()).create();
        assertTrue(revocationDataVerifier.isAcceptable(ocspToken));

        CryptographicConstraint cryptographicRevocationConstraint = validationPolicy.getRevocationConstraints()
                .getBasicSignatureConstraints().getCryptographic();

        cryptographicRevocationConstraint.getAcceptableDigestAlgo().getAlgos().clear();

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).setValidationTime(calendar.getTime()).create();
        assertFalse(revocationDataVerifier.isAcceptable(ocspToken));
    }

    @Test
    public void encryptionAlgorithmWithValidationPolicyTest() throws Exception {
        String certB64 = "MIID1DCCArygAwIBAgIBCjANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjEwNzAzMTI1MTQ0WhcNMjMwNTAzMTI1MTQ0WjBPMRIwEAYDVQQDDAlnb29kLXVzZXIxGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM/yDHvOV9Ju5wPnzpYOP+n02Af3lYsE9lfICMRAlYpySE97ty1Tk6/UJ6mw6vvsNMkBd2by0Kqx3/P5aXPkrXprguaRA+R5LgbRa0fWJMhrjmPE4qCNHJ6qZyRe7oxE3ovzX+voNt+bvncs0TtNvXXkUZ02rS28wf7gOIVc8z0GPAqN7ccw1eUQ/lVmfmuDTa5Ftn2bbuwp8Y3LwxTDxKITHgMMA2BNFcFo9f5DgQ0gqyTwPhJHKLXkxB1hwNTtuFzVI3+UBv3dI5Xe3F0pjlPLjjj/25gsTWe5vAIljQVR5ATlT82GtbhfbRB+T1SoRmODGEiKTilkxGEaWOpvKcsCAwEAAaOBvDCBuTAOBgNVHQ8BAf8EBAMCBkAwgYcGCCsGAQUFBwEBBHsweTA5BggrBgEFBQcwAYYtaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3Rvcnkvb2NzcC9nb29kLWNhMDwGCCsGAQUFBzAChjBodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvZ29vZC1jYS5jcnQwHQYDVR0OBBYEFHCHitKwTKLLmAH4oK8ZoA21kfztMA0GCSqGSIb3DQEBCwUAA4IBAQBmLhBm5s2VqW2XQcXH4oWbc+IV0Tafhnh8nWpNDGlYNlh1GPuNrrs4zDcYrmgMH5BrtBw5/HAJUZjRLYyBQBxjAdtBtHgcoIzv/QbSVStuJdVIEJyFB8mPSzOEAYJSdwF9ciwkdjgA+fMczova37zIrLxLTw+qkxsXYrddWDA08koo15Gsug5OyfQbGvsx1ctag4IelUAeXkXSodOaZxroRJzNXE32xFz9GQwVqBxyTMFyEfo3g5lwGnhGilopksBoStoTKZXXUkqyg1TVULEA7ppq0KPgWgeYCO1xKX6hediDnwKf1oWQXMtS3+34fh8HuDKpXHSbVmsC26cxhIre";
        String caCertB64 = "MIID6jCCAtKgAwIBAgIBBDANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjEwNzAzMTI1MTQzWhcNMjMwNTAzMTI1MTQzWjBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCxf8STorHasImct8bY+CFmxdm7JaM1/4peMPOs2FTgjq3OnbILB7wXYznGpbJqNGVLV0bWFrgbKeQcOU1xFta4HJxVH9a5CdO1g7HiYTCLOKD/4fKSlw5xWB+oD0Tgs8R56Kp3esBiQ2uFZ6X18XM7SbXZof4P7qu1TkosKvVXNkI70g4pajt4z5dNwruGHpKgVx5o31MBYRdNYQ918OS0NXPhP9N/U8P/v2Fx3W/sohn1nISKBYDOxHYSfQks2zdjJ/A+i/5hodPkijkmTAP0oCcvIymUkeoJxTqpAFwCvj3I+ZT7LWr1ESfi/ZU0pUAcipz96L7vX8+/9GdH/GV1AgMBAAGjgdQwgdEwDgYDVR0PAQH/BAQDAgEGMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NybC9yb290LWNhLmNybDBMBggrBgEFBQcBAQRAMD4wPAYIKwYBBQUHMAKGMGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NydC9yb290LWNhLmNydDAdBgNVHQ4EFgQUqvu5WABNumd2cDVEWyzGnvihBOkwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAUa1Vot6evQWOJqxqKpM5T1tK/DPMfEPpWISaeOHn0RHKKGMgwct2uTpQhd+CoD7WAGJk41DKtDMSmz5Dkpj/Z7irWoSn55PtrnhA5xedGYgJAZzUYZoJqB2VqPgnUtaWWI+R5vhvuz6Ob8SFIdFb/k8qe4EbkTB9eA/UGKS9RjngepsqCHroXIGiJD/xvVz69iLADmwRBQdWx4N+ZXpF67YgiK2wHq9psE/S/ExMfZPXrrCf4bPagvgEUYE3ZKhUsUOJDk+gmVAYUa/V5ZBESMW+uiI/MqtyEMIysdwqW32EkaIEdunPj1VQY+m+SOlKs9jD/8b0KKL/hkRvTMhl4Q==";
        String ocspTokenB64 = "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";

        ExternalResourcesOCSPSource ocspSource = new ExternalResourcesOCSPSource(new InMemoryDocument(Utils.fromBase64(ocspTokenB64)));
        List<RevocationToken<OCSP>> revocationTokens = ocspSource.getRevocationTokens(DSSUtils.loadCertificateFromBase64EncodedString(certB64), DSSUtils.loadCertificateFromBase64EncodedString(caCertB64));
        assertEquals(1, revocationTokens.size());

        RevocationToken<OCSP> ocspToken = revocationTokens.iterator().next();

        ValidationPolicy validationPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        CryptographicConstraint cryptographic = validationPolicy.getCryptographic();
        cryptographic.setLevel(Level.IGNORE);

        RevocationDataVerifier revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertTrue(revocationDataVerifier.isAcceptable(ocspToken));

        validationPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        cryptographic = validationPolicy.getCryptographic();
        cryptographic.setLevel(Level.FAIL);

        ListAlgo acceptableEncryptionAlgo = cryptographic.getAcceptableEncryptionAlgo();
        acceptableEncryptionAlgo.getAlgos().clear();

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertFalse(revocationDataVerifier.isAcceptable(ocspToken));

        Algo algo = new Algo();
        algo.setValue("RSA");
        acceptableEncryptionAlgo.getAlgos().add(algo);

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertTrue(revocationDataVerifier.isAcceptable(ocspToken));

        ListAlgo miniPublicKeySize = cryptographic.getMiniPublicKeySize();
        miniPublicKeySize.getAlgos().clear();

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertFalse(revocationDataVerifier.isAcceptable(ocspToken));

        algo.setSize(3000);
        miniPublicKeySize.getAlgos().add(algo);

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertFalse(revocationDataVerifier.isAcceptable(ocspToken));

        algo.setSize(1900);

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertTrue(revocationDataVerifier.isAcceptable(ocspToken));

        AlgoExpirationDate algoExpirationDate = cryptographic.getAlgoExpirationDate();
        algoExpirationDate.setFormat("yyyy");

        algo.setDate("2025");
        algoExpirationDate.getAlgos().add(algo);

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertTrue(revocationDataVerifier.isAcceptable(ocspToken));

        algo.setDate("2015");

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertFalse(revocationDataVerifier.isAcceptable(ocspToken));

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(Calendar.YEAR, 2000);

        revocationDataVerifier.setAcceptableEncryptionAlgorithmKeyLength(Collections.singletonMap(EncryptionAlgorithm.RSA, 2048));
        assertTrue(revocationDataVerifier.isAcceptable(ocspToken));

        CryptographicConstraint cryptographicRevocationConstraint = validationPolicy.getRevocationConstraints()
                .getBasicSignatureConstraints().getCryptographic();

        cryptographicRevocationConstraint.getAcceptableEncryptionAlgo().getAlgos().clear();

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).setValidationTime(calendar.getTime()).create();
        assertFalse(revocationDataVerifier.isAcceptable(ocspToken));
    }

    @Test
    public void revocationSkipValAssuredCertTest() throws Exception {
        CertificateToken shortTermCertificate = DSSUtils.loadCertificateFromBase64EncodedString(
                "MIIDJjCCAg6gAwIBAgIIMMSTGSdLPxQwDQYJKoZIhvcNAQENBQAwKDEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczELMAkGA1UEBhMCTFUwHhcNMjEwNzAxMTAwMTI5WhcNMjEwNzAxMTAwNjI5WjA2MQwwCgYDVQQDDANBIGExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxCzAJBgNVBAYTAkxVMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsW0yfJBqh9CtbfOtsZcEAEvzzfPusdhZNv0JSq8frKGMqJwTgjnkMJd9D3sEHUBJP0ryAmK9L5S+lWOGDhdYcE8K00k3hZSHyrOdRblB0SZhtXIgeGD7ESdTU9xPCf4Ze7xSI08zlk9NmTaj5Xqfyako8sxHAQapdXw8kfG0Ol6UhfMg7MjN8/wZrIVUYZzBQP3RFKHFQIms+pxfWxvETsynn/n2rOjuAsV0aTWGUAeWJRFJxKLSTrHQiQULVS1MHIIkdbQZxMA+Jn3dXwVdJLX/JRSvEOBqGRrvGQtYN2vNdrJlNHP0WGcSAddweWs7Ar+Pp7Qm/HEQF5+EOPUQDQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCBsAwIwYIKwYBBQUHAQMEFzAVMBMGBgQAjkYBBjAJBgcEAI5GAQYBMA0GBwQAi+xJAgEEAgUAMA0GCSqGSIb3DQEBDQUAA4IBAQBAYj8mdKsj/mMoM4HXL/w+xeK0iM55eGyBNprwxECoCH8ZCgVrVTb3eKttTXYrXjk3Yqpg3amkm7aV94iXJ0qLER/2C9lHLv6h1CoxYCdevAUSVOIzF0SJj54dxrwDQ7uTFXRe2etOg+hmEhj3OBpd/5vMfdIViYHtpPoCyZoQyGLztUt1k8/JvBe91UGAEnWx0nvokehkTgueq7dsTjBit4dlCmfmIzQUUWCgNpe1S1nEb0B/BCXaqPRhYx1//2T/5gR1lKe36HHp5rUURKT8NsS76lfxdor9Ag3mVmsw1NcVtDiFo0molO84+B53yqRP2wCU7MtfKfCX9CocgVNF");

        ValidationPolicy validationPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        CertificateConstraints signingCertificate = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();

        CertificateValuesConstraint certificateValuesConstraint = new CertificateValuesConstraint();
        signingCertificate.setRevocationDataSkip(certificateValuesConstraint);

        signingCertificate = validationPolicy.getCounterSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        signingCertificate.setRevocationDataSkip(certificateValuesConstraint);

        RevocationDataVerifier revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertFalse(revocationDataVerifier.isRevocationDataSkip(shortTermCertificate));

        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add(OID.id_etsi_ext_valassured_ST_certs.getId());
        certificateValuesConstraint.setCertificateExtensions(multiValuesConstraint);
        signingCertificate.setRevocationDataSkip(certificateValuesConstraint);

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertTrue(revocationDataVerifier.isRevocationDataSkip(shortTermCertificate));

        revocationDataVerifier.setRevocationSkipCertificateExtensions(Collections.emptyList());
        assertFalse(revocationDataVerifier.isRevocationDataSkip(shortTermCertificate));

        revocationDataVerifier.setRevocationSkipCertificateExtensions(
                Collections.singleton(OID.id_etsi_ext_valassured_ST_certs.getId()));
        assertTrue(revocationDataVerifier.isRevocationDataSkip(shortTermCertificate));

        revocationDataVerifier.setRevocationSkipCertificateExtensions(
                Collections.singleton(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()));
        assertFalse(revocationDataVerifier.isRevocationDataSkip(shortTermCertificate));

        revocationDataVerifier.setRevocationSkipCertificateExtensions(
                Arrays.asList(OID.id_etsi_ext_valassured_ST_certs.getId(), OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()));
        assertTrue(revocationDataVerifier.isRevocationDataSkip(shortTermCertificate));
    }

    @Test
    public void revocationSkipOcspNoCheckTest() throws Exception {
        CertificateToken ocspNoCheckCertificate = DSSUtils.loadCertificateFromBase64EncodedString(
                "MIIEXjCCAkagAwIBAgILBAAAAAABWLd6HkYwDQYJKoZIhvcNAQELBQAwMzELMAkGA1UEBhMCQkUxEzARBgNVBAMTCkNpdGl6ZW4gQ0ExDzANBgNVBAUTBjIwMTYzMTAeFw0xNjEyMTAxMTAwMDBaFw0xODAxMjkxMTAwMDBaMC4xHzAdBgNVBAMTFkJlbGdpdW0gT0NTUCBSZXNwb25kZXIxCzAJBgNVBAYTAkJFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzD0B0c4gBx/wumeE2l/Wcz5FoMSUIuRNIySH2pJ3yfKR/u/FWCOzcrJvDMdmgzR33zGb4/fZel9YlI6xcN08Yd7GkP0/WtbHUhGUPERV76Vvyrk2K/EH/IG2gtxYB+7pkA/ZZycdyjc4IxHzBOiGofP9lDkPD05GSqI7MjVf6sNkZSnHcQSKwkaCGhAshJMjHzShEsSzOgX9kXceBFPTt6Hd2prVmnMTyAwURbQ6gFHbgfxB8JLMya95U6391nGQC66ScH1GhIwd9KSn+yBY0cazJ3nIrc8wd0yGYBgPK78jN3MvAsb1ydfs7kE+Wf95z9oRMiw62Glxh/ksLS/tTQIDAQABo3gwdjAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFBgKRBywCTroyvAErr7p657558Y9MBMGA1UdJQQMMAoGCCsGAQUFBwMJMB8GA1UdIwQYMBaAFM6Al2fQrdlOxJlqgCcikM0RNRCHMA8GCSsGAQUFBzABBQQCBQAwDQYJKoZIhvcNAQELBQADggIBAFuZrqcwt23UiiJdRst66MEBRyKbgPsQM81Uq4FVrAnV8z3l8DDUv+A29KzCPO0GnHSatqA7DNhhMzoBRC42PqCpuvrj8VEWHd43AuPOLaikE04a5tVh6DgW8b00s6Yyf/PuDHCsg2C2MqY71MUR9GcnI7ngR2SyWQGpbsf/wfjujNxEB0+SOwMDTgIAikaueHGZbYkwvlRpL6wm2ENvrE8OvKt7NlNsaWJ4KtQo0QS5Ku+Y2BDA3bX+g8eNLQkaXTycgL4X3MyE5pBOl1OW3KOjJdfyLF+Sii+JKjNf8ZQWk0xvkBEI+nhCzDXhtKAcrkTKlXE25MiUnYoRsXkXgrzYftxAMxvFOXJji/hnX5Fe/3SBAHaE+jU6yC5nk6Q9ERii8mL0nHouMlZWSiAuXtlZDFrzwtLD2ITBECe4X60BDQfb/caO2u3HcWoG1AOvGxfQB0cMmP2njCdDf8UOqryiyky4t7Jj3ghOvETjWlwMw5ObhZ8yj8p6qFAt7+EVJfpUc1gDAolS/hJoLzohbL5LnCAnUAWsFpvG3qW1ky+X0MePXi6q/boqj2tcC4IDdsYS6RHPBvzl5+yLDccrGx1s/7vQYTMNyX0dYZzuxFZxx0bttWfjqLz3hFHlAEVmLCyUkSz761CbaT9u/G4tPP4Q8ApFfSskPI57lbLWIcwP");

        RevocationDataVerifier revocationDataVerifier = RevocationDataVerifier.createDefaultRevocationDataVerifier();
        assertTrue(revocationDataVerifier.isRevocationDataSkip(ocspNoCheckCertificate));

        ValidationPolicy validationPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        CertificateConstraints signingCertificate = validationPolicy.getRevocationConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();

        CertificateValuesConstraint certificateValuesConstraint = new CertificateValuesConstraint();
        signingCertificate.setRevocationDataSkip(certificateValuesConstraint);

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertFalse(revocationDataVerifier.isRevocationDataSkip(ocspNoCheckCertificate));

        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId());
        certificateValuesConstraint.setCertificateExtensions(multiValuesConstraint);
        signingCertificate.setRevocationDataSkip(certificateValuesConstraint);

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertTrue(revocationDataVerifier.isRevocationDataSkip(ocspNoCheckCertificate));

        revocationDataVerifier.setRevocationSkipCertificateExtensions(
                Collections.singleton(OID.id_etsi_ext_valassured_ST_certs.getId()));
        assertFalse(revocationDataVerifier.isRevocationDataSkip(ocspNoCheckCertificate));

        revocationDataVerifier.setRevocationSkipCertificateExtensions(
                Collections.singleton(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()));
        assertTrue(revocationDataVerifier.isRevocationDataSkip(ocspNoCheckCertificate));

        revocationDataVerifier.setRevocationSkipCertificateExtensions(
                Arrays.asList(OID.id_etsi_ext_valassured_ST_certs.getId(), OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()));
        assertTrue(revocationDataVerifier.isRevocationDataSkip(ocspNoCheckCertificate));
    }

    @Test
    public void revocationSkipPolicyTest() throws Exception {
        String certB64 = "MIIFQDCCBCigAwIBAgIOGCB2t4Cg4gEAAQAOEN4wDQYJKoZIhvcNAQELBQAwbTELMAkGA1UEBhMCTFQxEjAQBgNVBGETCTE4ODc3ODMxNTE2MDQGA1UEChMtQXNtZW5zIGRva3VtZW50dSBpc3Jhc3ltbyBjZW50cmFzIHByaWUgTFIgVlJNMRIwEAYDVQQDEwlBRElDIENBLUEwHhcNMTkwMTE1MDc1MDUwWhcNMjIwMTE0MDc1MDUwWjBlMQswCQYDVQQGEwJMVDEaMBgGA1UEAwwRQURPTUFTIEJJUsWgVFVOQVMxEzARBgNVBAQMCkJJUsWgVFVOQVMxDzANBgNVBCoTBkFET01BUzEUMBIGA1UEBRMLMzgwMDMxMzA2OTMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpBBVaIBn1jxl44uuvkJWkW5F3rtoUsmAkMJPlPyzQOg87h07uYOIJk4YDIpvujDaL3y3RAy7ARFWpY31zn0b0TnMkDyuf5JYtro6ZpR3v/wijVUNYyGZYpbc42WVNVp/AYuE6IJ7ecE1dMMJDHVkJAmoH2wnT+Lnqp71n51luYc5v0VP+OFmPqPzuSbiwXewOg8PHARkv9l8d0FnoUmKg5xpm+jbjCFsOC77hkwjUDQxu9Yv7p+T1X7+se46GDOm287i2iW66bZYu4qy6ycrznNuwWLtU1i5Z7ypoNGJ++IRn4wP80CvwzUo5TNcLD8Ql3PaDs8GPKXfpBz2zd4MBAgMBAAGjggHkMIIB4DBLBgNVHQkERDBCMA8GCCsGAQUFBwkDMQMTAU0wHQYIKwYBBQUHCQExERgPMTk4MDAzMTMxMjAwMDBaMBAGCCsGAQUFBwkEMQQTAkxUMB0GA1UdDgQWBBSkKwML7BV258Cpil5bewoD6itogjAOBgNVHQ8BAf8EBAMCBsAwHwYDVR0jBBgwFoAUYpbcZMVf8JBEU79q1WAACu/0N7IweAYIKwYBBQUHAQEEbDBqMDQGCCsGAQUFBzABhihodHRwOi8vbnNjLnZybS5sdC9PQ1NQL29jc3ByZXNwb25kZXIubnNjMDIGCCsGAQUFBzAChiZodHRwOi8vbnNjLnZybS5sdC9haWEvQURJQ19DQS1BKDEpLmNydDAVBgNVHSUEDjAMBgorBgEEAYI3CgMMMEQGA1UdIAQ9MDswOQYLKwYBBAGChlUCAgIwKjAoBggrBgEFBQcCARYcaHR0cDovL25zYy52cm0ubHQvcmVwb3NpdG9yeTAdBgkrBgEEAYI3FQoEEDAOMAwGCisGAQQBgjcKAwwwSwYIKwYBBQUHAQMEPzA9MAgGBgQAjkYBATAIBgYEAI5GAQQwJwYGBACORgEFMB0wGxYVaHR0cDovL25zYy52cm0ubHQvcGRzEwJlbjANBgkqhkiG9w0BAQsFAAOCAQEAIHcOUDrDtW1cJVkCsKpdniYpBBoZfmwX0VIM+mTevRb/dCTMyHHp+DkfauWXEGUEkl+PoZb8r9hoYcBWYvbIXbSEPnoRX26BLXeNGKz4LxqoqoHRqDFSOr7+7uFkhIwalM5mjc9c/oOJZu5xTALH/TCSRD4TVp48/+UiII/JpC+700N8oNbPkJUoKBpfRFcD89WGlvywrGYyD1nPoSn+KF7lmxenl+KEJKE6q0UdzV9kbzkk7BlksiUL9U9D0c7emx6pRk1Mw7fqTVD/ETGqmKVR6lzIQcY/GLQ55W968FrovU6F7TP/7qW8ahYzdM09sEnoIeG5jet3mYVHPEyGMA==";
        CertificateToken certificateToken = DSSUtils.loadCertificateFromBase64EncodedString(certB64);

        RevocationDataVerifier revocationDataVerifier = RevocationDataVerifier.createDefaultRevocationDataVerifier();
        assertFalse(revocationDataVerifier.isRevocationDataSkip(certificateToken));

        ValidationPolicy validationPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        CertificateConstraints signingCertificate = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();

        CertificateValuesConstraint certificateValuesConstraint = new CertificateValuesConstraint();
        signingCertificate.setRevocationDataSkip(certificateValuesConstraint);

        signingCertificate = validationPolicy.getCounterSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        signingCertificate.setRevocationDataSkip(certificateValuesConstraint);

        assertFalse(revocationDataVerifier.isRevocationDataSkip(certificateToken));

        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("1.3.6.1.4.1.33621.2.2.2");
        certificateValuesConstraint.setCertificatePolicies(multiValuesConstraint);
        signingCertificate.setRevocationDataSkip(certificateValuesConstraint);

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertTrue(revocationDataVerifier.isRevocationDataSkip(certificateToken));

        revocationDataVerifier.setRevocationSkipCertificatePolicies(
                Collections.singleton("1.3.6.1.4.1.33621.2.2.2"));
        assertTrue(revocationDataVerifier.isRevocationDataSkip(certificateToken));

        revocationDataVerifier.setRevocationSkipCertificatePolicies(
                Collections.singleton("1.2.3.4.5"));
        assertFalse(revocationDataVerifier.isRevocationDataSkip(certificateToken));

        revocationDataVerifier.setRevocationSkipCertificatePolicies(
                Arrays.asList("1.3.6.1.4.1.33621.2.2.2", "1.2.3.4.5"));
        assertTrue(revocationDataVerifier.isRevocationDataSkip(certificateToken));
    }

    @Test
    public void revocationFreshnessConstraintFromPolicyTest() throws Exception {
        String certB64 = "MIIE1zCCAr+gAwIBAgIDTB3fMA0GCSqGSIb3DQEBCwUAME4xCzAJBgNVBAYTAkxVMRYwFAYDVQQKDA1MdXhUcnVzdCBTLkEuMScwJQYDVQQDDB5MdXhUcnVzdCBHbG9iYWwgUXVhbGlmaWVkIENBIDMwHhcNMjIwMjAyMTMzMTU0WhcNMjMwMjAyMTMzMTU0WjBeMQswCQYDVQQGEwJMVTEWMBQGA1UEChMNTHV4VHJ1c3QgUy5BLjETMBEGA1UECxMKUGtpIGVudGl0eTEiMCAGA1UEAxMZTHV4VHJ1c3QgUy5BLiBPQ1NQIFNlcnZlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALXRJgqc3YegdIDHbBKRUSU3HJ9BneUEOgro2UuEiL5LzGMmShHPxSwwGNgAPCIsQdFrEipDfXzEf82ZMbh58xB4wJy/aKo+RniImvqZMy7TctHfi5PrloMvV1rR3AUuMyod5jAr0DTrVwfVBKHWn2f+dvI5Utelye8vVtc40o3UFvcLmrm8/+kS14tsoUyC8ybv1u33CrZOeFdjmdkYZsvtQcdH5kU8KEWiQlkRze54pwbYpkU3YolCqVvng37QUIkkaLtKimt39akJE8v4eSmJdd7d+7XXiC4NGnKPj8KtaXtVVggqji5FHaOdTE22Sv6nQofcX2CNts7k3ge6QysCAwEAAaOBrTCBqjATBgNVHSUEDDAKBggrBgEFBQcDCTAfBgNVHSMEGDAWgBRjj8KLA7GrjthTR5Ydmah99qyodTA4BgNVHR8EMTAvMC2gK6AphidodHRwOi8vY3JsLmx1eHRydXN0Lmx1L0xUR1FDQTMtT0NTUC5jcmwwHQYDVR0OBBYEFAgSTQgLkHHOjcK2da1yHo5lnnaWMA4GA1UdDwEB/wQEAwIHgDAJBgNVHRMEAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQCdN3AmbWYNy0ZfU038pnOYXVsQ8KnVWZUht73/VFu/kaBix9IWSFfQ5y+duae9MkByi/TQbXk6mFYfCFfr2I3GaYAhyxtuWoCQg84BeqIASX3cNVrCABn8GIEsPsFDuUXXLFZ5uIY/uPjACB3AclbM4O9COD7CFVZAXCl/+CcC9M68AnfSf6zBIYnBM3QZde35IVj0Y5ZRg5DnC2zsICkIqCbQDoDSBVTWkdH20tA9zMEgLgZSk9W1ablOmRdo5+3HmHQ4+CN7Xxd3aoprAqsdlLpL8/PupDQ6dTL1VxfycQQEUodztmW7hRqg5mp87P0X9sbNXNVJCEzaa6LZlQ04FnA7uVIEntmqlOubyGpcbziX9mLrrPHcfUqEShA4h7hJmQK5paLkK/YDFDs6uZpnyRLv+7dT5l3fu5KvEEe75ZKzPfF+fNg8Iu9ADpcFLyHuUPlEqRW4KTEfmJK/RVAnUVbqFG1nlLSbSj658lCoJtJ597GuNEJ5nipAxH4PM6dE9+P0xBWvOFs1+xnplRYVnx+ElITfzHLRJVchTCw1SOcPll+Ro4qA/4IslarWpE8V388B7KMmsfMS6sSmWpEAQxjvruabSAc/baIzTbqXQFAVXzJWuBeYto2URIl6+3XA+Bca8hOkNBNUvIcAevg6oL24x1oLvB0av+RG8Ly3wA==";
        String caCertB64 = "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";
        String crlTokenB64 = "MIIDBDCB7QIBATANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJMVTEWMBQGA1UECgwNTHV4VHJ1c3QgUy5BLjEnMCUGA1UEAwweTHV4VHJ1c3QgR2xvYmFsIFF1YWxpZmllZCBDQSAzFw0yMTA2MTgwNDQ5MTlaFw0yMTA2MTgwOTE5MTlaoGswaTA5BgNVHRwBAf8ELzAtoCugKYYnaHR0cDovL2NybC5sdXh0cnVzdC5sdS9MVEdRQ0EzLU9DU1AuY3JsMAsGA1UdFAQEAgJjvjAfBgNVHSMEGDAWgBRjj8KLA7GrjthTR5Ydmah99qyodTANBgkqhkiG9w0BAQsFAAOCAgEArGXGqX6Km4r4wkTjnrTbVvTb/a0cQG3dXNYBzOhqe0/8C/22G9CHe5OniPLetlq/qBZrMdAWWlMk0WF2Xzd4xu+i2jn4U5e7WcKMC59b9v9453YZE3tBtKMGJ2uapevSxvgsAk25xjXT1pwhI7Aiqs9XLuTrJYIboTQKorwzYzWz5gdYsw41pdgvuu/OXZyNBVUXqCiDLPJdtSnOQEJwPUOnW8drk8mWlfe+7Ml8IJKbXzD0DP1fE8xXdgUshWiOd8cfM7KdpD2tViefMa9uXvDG3etH0bOu4dt09hU64s2mCmRlDWkcrIMH8+vmCXf8Fgx/cTk4hiKlVZBZzJBgPvQI+8FJhM77sQg6FjjaGoQLqUWYpKAVLynOjEw/POLT8H5WhBKC+/G5du+nSxCGgl/fcflkyIX9Wr144xQjyDK1CL935fnbFFavwXeCLxqM1MZML8lDltTCPTlxBtSBgRPRSOh5J9ibqAlwZvD/awwnix/UVUr1VXdTJSQR+5LDa4tpbUqQK7O+wMHA3Zrfo9/HWKhb2zcYLITVBDuwOKjelYNe2Lxg1jOzTclG4T9nSSTPEdchPvBlsqlnOwmle15Zu2/QSva+gfzHcbDmEwMzEwhiDz+7ndMkaiNCdIl8/KShC3l9B/pElI0wSJpSYNn1ILUcZbRe9sSr3eJjaOo=";

        ExternalResourcesCRLSource crlSource = new ExternalResourcesCRLSource(new InMemoryDocument(Utils.fromBase64(crlTokenB64)));
        List<RevocationToken<CRL>> revocationTokens = crlSource.getRevocationTokens(DSSUtils.loadCertificateFromBase64EncodedString(certB64), DSSUtils.loadCertificateFromBase64EncodedString(caCertB64));
        assertEquals(1, revocationTokens.size());

        RevocationToken<CRL> crlToken = revocationTokens.iterator().next();

        RevocationDataVerifier revocationDataVerifier = RevocationDataVerifier.createDefaultRevocationDataVerifier();
        assertFalse(revocationDataVerifier.isRevocationDataFresh(crlToken, new Date(), Context.SIGNATURE));
        assertFalse(revocationDataVerifier.isRevocationDataFresh(crlToken, new Date(), Context.TIMESTAMP));
        assertFalse(revocationDataVerifier.isRevocationDataFresh(crlToken, new Date(), Context.REVOCATION));

        ValidationPolicy validationPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertFalse(revocationDataVerifier.isRevocationDataFresh(crlToken, new Date(), Context.SIGNATURE));
        assertFalse(revocationDataVerifier.isRevocationDataFresh(crlToken, new Date(), Context.TIMESTAMP));
        assertFalse(revocationDataVerifier.isRevocationDataFresh(crlToken, new Date(), Context.REVOCATION));

        Calendar calendar = Calendar.getInstance();
        calendar.set(2021, Calendar.JUNE, 18, 8, 0);
        assertFalse(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.SIGNATURE));
        assertFalse(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.TIMESTAMP));
        assertFalse(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.REVOCATION));

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate().setRevocationFreshnessNextUpdate(levelConstraint);
        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();

        assertFalse(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.SIGNATURE));
        assertFalse(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.TIMESTAMP));
        assertFalse(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.REVOCATION));

        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate().setRevocationFreshness(null);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().getCACertificate().setRevocationFreshness(null);
        validationPolicy.getCounterSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate().setRevocationFreshness(null);
        validationPolicy.getCounterSignatureConstraints().getBasicSignatureConstraints().getCACertificate().setRevocationFreshness(null);
        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints().getSigningCertificate().setRevocationFreshness(null);
        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints().getCACertificate().setRevocationFreshness(null);
        validationPolicy.getRevocationConstraints().getBasicSignatureConstraints().getSigningCertificate().setRevocationFreshness(null);
        validationPolicy.getRevocationConstraints().getBasicSignatureConstraints().getCACertificate().setRevocationFreshness(null);
        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();

        assertTrue(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.SIGNATURE));
        assertTrue(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.TIMESTAMP));
        assertTrue(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.REVOCATION));

        calendar.set(2021, Calendar.JUNE, 18, 23, 59);
        assertFalse(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.SIGNATURE));
        assertFalse(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.TIMESTAMP));
        assertFalse(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.REVOCATION));

        TimeConstraint timeConstraint = new TimeConstraint();
        timeConstraint.setUnit(TimeUnit.HOURS);
        timeConstraint.setValue(24);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate().setRevocationFreshness(timeConstraint);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().getCACertificate().setRevocationFreshness(timeConstraint);
        validationPolicy.getCounterSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate().setRevocationFreshness(timeConstraint);
        validationPolicy.getCounterSignatureConstraints().getBasicSignatureConstraints().getCACertificate().setRevocationFreshness(timeConstraint);

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertTrue(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.SIGNATURE));
        assertFalse(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.TIMESTAMP));
        assertFalse(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.REVOCATION));

        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints().getSigningCertificate().setRevocationFreshness(timeConstraint);
        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints().getCACertificate().setRevocationFreshness(timeConstraint);

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertTrue(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.SIGNATURE));
        assertTrue(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.TIMESTAMP));
        assertFalse(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.REVOCATION));

        validationPolicy.getRevocationConstraints().getBasicSignatureConstraints().getSigningCertificate().setRevocationFreshness(timeConstraint);
        validationPolicy.getRevocationConstraints().getBasicSignatureConstraints().getCACertificate().setRevocationFreshness(timeConstraint);

        revocationDataVerifier = new RevocationDataVerifierFactory(validationPolicy).create();
        assertTrue(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.SIGNATURE));
        assertTrue(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.TIMESTAMP));
        assertTrue(revocationDataVerifier.isRevocationDataFresh(crlToken, calendar.getTime(), Context.REVOCATION));
    }

}
