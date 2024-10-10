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
import eu.europa.esig.dss.model.tsl.CertificateTrustTime;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.validation.TrustAnchorVerifier;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrustAnchorVerifierFactoryTest {

    @Test
    void sunsetDateTest() throws Exception {
        String certB64 = "MIID2jCCAzygAwIBAgIQEQmhFq6e3gQzhrtuqx1sKjAKBggqhkjOPQQDBDCBiDELMAkGA1UEBhMCQ1IxJjAkBgNVBAoMHUhlcm1lcyBTb2x1Y2lvbmVzIGRlIEludGVybmV0MRYwFAYDVQQLDA1GaXJtYSBkaWdpdGFsMR8wHQYDVQQDDBZBQyBwb2xpdGljYSBUU0EgSGVybWVzMRgwFgYDVQQFEw9DUEotMy0xMDEtOTE4MTAwHhcNMjEwMzMwMTc1MjQ1WhcNMzIwMzI3MTc1MjQ1WjB8MQswCQYDVQQGEwJDUjEmMCQGA1UECgwdSGVybWVzIFNvbHVjaW9uZXMgZGUgSW50ZXJuZXQxFjAUBgNVBAsMDUZpcm1hIERpZ2l0YWwxEzARBgNVBAMMCkhlcm1lcyBUU0ExGDAWBgNVBAUTD0NQSi0zLTEwMS05MTgxMDCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAHDK7hU/w3gbDuoo5Vqcaiz5ME95lHdOWUM65TuY0mnHZPCjimYW37jcKEYPafUCAupRaElO5LPggKxHfGLQK9fjAanRlTxIPmAl68SkpwYfIxeZeBvpfymVsg87YASTv3PY3lLLFi0i4U0/aO2jA92UGeNT+uelidcy9F/1ErOcSsrVo4IBTjCCAUowHwYDVR0jBBgwFoAUVm4BgFh89eU+jDQ3k5yB/Vw3LvcwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCBkAwHQYDVR0OBBYEFGEm1wgsmDICKVBvr44pLjsmbRAfMIGOBggrBgEFBQcBAQSBgTB/MDwGCCsGAQUFBzAChjBodHRwczovL2FwcC5maXJtYS1kaWdpdGFsLmNyL2ZpbGVzL2FjLXRzYS12MS5jcnQwPwYIKwYBBQUHMAGGM2h0dHBzOi8vYXBwLmZpcm1hLWRpZ2l0YWwuY3IvaGFwaS9hYy9vY3NwL2FjLXRzYS12MTBBBgNVHR8EOjA4MDagNKAyhjBodHRwczovL2FwcC5maXJtYS1kaWdpdGFsLmNyL2ZpbGVzL2FjLXRzYS12MS5jcmwwCgYIKoZIzj0EAwQDgYsAMIGHAkFKqSNFeD7W9Gpf1fVaaE/ki58f4QDnrGsM3E1UHyryI9z6S5IVxIu2QCE6gwKRGYWopj1fdIFQeAC/R0ZNgXQAHgJCATx4P1dt/2iLQ4nfunRDgji3TpCFh0qZYw+N+RVs2SlVzRCzeujeLCOFyR92HBODZXx8ERUpT7r6MYou9kVCuJQL";
        String caCertB64 = "MIIDwzCCAyWgAwIBAgIQchZPmvJqypVzPW25na7FpDAKBggqhkjOPQQDBDCBgzELMAkGA1UEBhMCQ1IxJjAkBgNVBAoMHUhlcm1lcyBTb2x1Y2lvbmVzIGRlIEludGVybmV0MRYwFAYDVQQLDA1GaXJtYSBkaWdpdGFsMRowGAYDVQQDDBFBQyBSYWl6IEhlcm1lcyBWMTEYMBYGA1UEBRMPQ1BKLTMtMTAxLTkxODEwMB4XDTIxMDMzMDE3MDcwM1oXDTQ5MDMyMzE3MDcwM1owgYgxCzAJBgNVBAYTAkNSMSYwJAYDVQQKDB1IZXJtZXMgU29sdWNpb25lcyBkZSBJbnRlcm5ldDEWMBQGA1UECwwNRmlybWEgZGlnaXRhbDEfMB0GA1UEAwwWQUMgcG9saXRpY2EgVFNBIEhlcm1lczEYMBYGA1UEBRMPQ1BKLTMtMTAxLTkxODEwMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAqxLqeFumtOJYvc3yKKJXonOo2AMM2UgkFN6UQ9kT/xzeyasPZycP+jXG56QI49hm7elSxDDDbNl6p1xtOVCzVWoBf1YktAuelBkZAVtXomrmkgYRcjWSnZ3ktHDLAGi3gg2ODnABly4RijXlyHdGBj56KuXL6ByjFmH5FqXOlaqZ8P6jggEvMIIBKzCBhQYIKwYBBQUHAQEEeTB3MDgGCCsGAQUFBzAChixodHRwczovL2FwcC5maXJtYS1kaWdpdGFsLmNyL2ZpbGVzL2FjLXYxLmNydDA7BggrBgEFBQcwAYYvaHR0cHM6Ly9hcHAuZmlybWEtZGlnaXRhbC5jci9oYXBpL2FjL29jc3AvYWMtdjEwHwYDVR0jBBgwFoAUnOXvW9wXgKlvjgkLMo3NmjthWm0wEgYDVR0TAQH/BAgwBgEB/wIBADA9BgNVHR8ENjA0MDKgMKAuhixodHRwczovL2FwcC5maXJtYS1kaWdpdGFsLmNyL2ZpbGVzL2FjLXYxLmNybDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFFZuAYBYfPXlPow0N5Ocgf1cNy73MAoGCCqGSM49BAMEA4GLADCBhwJBD6XOKDHsm3C4vg7IR0s7pJEqy1WyBRBd8jNJDyFIHTNTiPwYPPr1yKajmQXFmWIaF0/53nbONb1qoGx69nn0RLsCQgFX/T7v79V4qiF359N2pKQ8LibHxuhCW2XzMEHiASNBFz03Puhk0NwBrhFRjx+q+jWqPBzCAw0D/lSBZzpMj3sDFQ==";

        CertificateToken certificateToken = DSSUtils.loadCertificateFromBase64EncodedString(certB64);
        CertificateToken caCertificate = DSSUtils.loadCertificateFromBase64EncodedString(caCertB64);

        List<CertificateToken> certificateChain = Arrays.asList(certificateToken, caCertificate);

        TrustAnchorVerifier trustAnchorVerifier = TrustAnchorVerifier.createDefaultTrustAnchorVerifier();
        assertFalse(trustAnchorVerifier.isTrustedAtTime(caCertificate, new Date()));
        assertFalse(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, new Date()));

        TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.YEAR, -1);
        Date startDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 2);
        Date endDate = calendar.getTime();

        Map<CertificateToken, List<CertificateTrustTime>> trustTimeByCertMap = new HashMap<>();

        trustTimeByCertMap.put(caCertificate, Collections.singletonList(new CertificateTrustTime(startDate, endDate)));
        trustedListsCertificateSource.setTrustTimeByCertificates(trustTimeByCertMap);
        trustAnchorVerifier.setTrustedCertificateSource(trustedListsCertificateSource);

        assertTrue(trustAnchorVerifier.isTrustedAtTime(caCertificate, new Date()));
        assertTrue(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, new Date()));

        calendar.add(Calendar.YEAR, 1);
        Date futureDate = calendar.getTime();

        assertFalse(trustAnchorVerifier.isTrustedAtTime(caCertificate, futureDate));
        assertFalse(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, futureDate));

        ValidationPolicy validationPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        trustAnchorVerifier = new TrustAnchorVerifierFactory(validationPolicy).create();
        trustAnchorVerifier.setTrustedCertificateSource(trustedListsCertificateSource);

        assertFalse(trustAnchorVerifier.isTrustedAtTime(caCertificate, futureDate));
        assertFalse(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, futureDate));

        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate().setSunsetDate(null);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().getCACertificate().setSunsetDate(null);
        validationPolicy.getCounterSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate().setSunsetDate(null);
        validationPolicy.getCounterSignatureConstraints().getBasicSignatureConstraints().getCACertificate().setSunsetDate(null);
        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints().getSigningCertificate().setSunsetDate(null);
        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints().getCACertificate().setSunsetDate(null);
        validationPolicy.getRevocationConstraints().getBasicSignatureConstraints().getSigningCertificate().setSunsetDate(null);
        validationPolicy.getRevocationConstraints().getBasicSignatureConstraints().getCACertificate().setSunsetDate(null);

        trustAnchorVerifier = new TrustAnchorVerifierFactory(validationPolicy).create();
        trustAnchorVerifier.setTrustedCertificateSource(trustedListsCertificateSource);

        assertTrue(trustAnchorVerifier.isTrustedAtTime(caCertificate, futureDate));
        assertTrue(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, futureDate));

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate().setSunsetDate(levelConstraint);

        trustAnchorVerifier = new TrustAnchorVerifierFactory(validationPolicy).create();
        trustAnchorVerifier.setTrustedCertificateSource(trustedListsCertificateSource);

        assertTrue(trustAnchorVerifier.isTrustedAtTime(caCertificate, futureDate));
        assertTrue(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, futureDate));

        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate().setSunsetDate(levelConstraint);

        trustAnchorVerifier = new TrustAnchorVerifierFactory(validationPolicy).create();
        trustAnchorVerifier.setTrustedCertificateSource(trustedListsCertificateSource);

        assertFalse(trustAnchorVerifier.isTrustedAtTime(caCertificate, futureDate));
        assertFalse(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, futureDate));
    }

    @Test
    void untrustedChainsTest() throws Exception {
        String certB64 = "MIID2jCCAzygAwIBAgIQEQmhFq6e3gQzhrtuqx1sKjAKBggqhkjOPQQDBDCBiDELMAkGA1UEBhMCQ1IxJjAkBgNVBAoMHUhlcm1lcyBTb2x1Y2lvbmVzIGRlIEludGVybmV0MRYwFAYDVQQLDA1GaXJtYSBkaWdpdGFsMR8wHQYDVQQDDBZBQyBwb2xpdGljYSBUU0EgSGVybWVzMRgwFgYDVQQFEw9DUEotMy0xMDEtOTE4MTAwHhcNMjEwMzMwMTc1MjQ1WhcNMzIwMzI3MTc1MjQ1WjB8MQswCQYDVQQGEwJDUjEmMCQGA1UECgwdSGVybWVzIFNvbHVjaW9uZXMgZGUgSW50ZXJuZXQxFjAUBgNVBAsMDUZpcm1hIERpZ2l0YWwxEzARBgNVBAMMCkhlcm1lcyBUU0ExGDAWBgNVBAUTD0NQSi0zLTEwMS05MTgxMDCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAHDK7hU/w3gbDuoo5Vqcaiz5ME95lHdOWUM65TuY0mnHZPCjimYW37jcKEYPafUCAupRaElO5LPggKxHfGLQK9fjAanRlTxIPmAl68SkpwYfIxeZeBvpfymVsg87YASTv3PY3lLLFi0i4U0/aO2jA92UGeNT+uelidcy9F/1ErOcSsrVo4IBTjCCAUowHwYDVR0jBBgwFoAUVm4BgFh89eU+jDQ3k5yB/Vw3LvcwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCBkAwHQYDVR0OBBYEFGEm1wgsmDICKVBvr44pLjsmbRAfMIGOBggrBgEFBQcBAQSBgTB/MDwGCCsGAQUFBzAChjBodHRwczovL2FwcC5maXJtYS1kaWdpdGFsLmNyL2ZpbGVzL2FjLXRzYS12MS5jcnQwPwYIKwYBBQUHMAGGM2h0dHBzOi8vYXBwLmZpcm1hLWRpZ2l0YWwuY3IvaGFwaS9hYy9vY3NwL2FjLXRzYS12MTBBBgNVHR8EOjA4MDagNKAyhjBodHRwczovL2FwcC5maXJtYS1kaWdpdGFsLmNyL2ZpbGVzL2FjLXRzYS12MS5jcmwwCgYIKoZIzj0EAwQDgYsAMIGHAkFKqSNFeD7W9Gpf1fVaaE/ki58f4QDnrGsM3E1UHyryI9z6S5IVxIu2QCE6gwKRGYWopj1fdIFQeAC/R0ZNgXQAHgJCATx4P1dt/2iLQ4nfunRDgji3TpCFh0qZYw+N+RVs2SlVzRCzeujeLCOFyR92HBODZXx8ERUpT7r6MYou9kVCuJQL";
        String caCertB64 = "MIIDwzCCAyWgAwIBAgIQchZPmvJqypVzPW25na7FpDAKBggqhkjOPQQDBDCBgzELMAkGA1UEBhMCQ1IxJjAkBgNVBAoMHUhlcm1lcyBTb2x1Y2lvbmVzIGRlIEludGVybmV0MRYwFAYDVQQLDA1GaXJtYSBkaWdpdGFsMRowGAYDVQQDDBFBQyBSYWl6IEhlcm1lcyBWMTEYMBYGA1UEBRMPQ1BKLTMtMTAxLTkxODEwMB4XDTIxMDMzMDE3MDcwM1oXDTQ5MDMyMzE3MDcwM1owgYgxCzAJBgNVBAYTAkNSMSYwJAYDVQQKDB1IZXJtZXMgU29sdWNpb25lcyBkZSBJbnRlcm5ldDEWMBQGA1UECwwNRmlybWEgZGlnaXRhbDEfMB0GA1UEAwwWQUMgcG9saXRpY2EgVFNBIEhlcm1lczEYMBYGA1UEBRMPQ1BKLTMtMTAxLTkxODEwMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAqxLqeFumtOJYvc3yKKJXonOo2AMM2UgkFN6UQ9kT/xzeyasPZycP+jXG56QI49hm7elSxDDDbNl6p1xtOVCzVWoBf1YktAuelBkZAVtXomrmkgYRcjWSnZ3ktHDLAGi3gg2ODnABly4RijXlyHdGBj56KuXL6ByjFmH5FqXOlaqZ8P6jggEvMIIBKzCBhQYIKwYBBQUHAQEEeTB3MDgGCCsGAQUFBzAChixodHRwczovL2FwcC5maXJtYS1kaWdpdGFsLmNyL2ZpbGVzL2FjLXYxLmNydDA7BggrBgEFBQcwAYYvaHR0cHM6Ly9hcHAuZmlybWEtZGlnaXRhbC5jci9oYXBpL2FjL29jc3AvYWMtdjEwHwYDVR0jBBgwFoAUnOXvW9wXgKlvjgkLMo3NmjthWm0wEgYDVR0TAQH/BAgwBgEB/wIBADA9BgNVHR8ENjA0MDKgMKAuhixodHRwczovL2FwcC5maXJtYS1kaWdpdGFsLmNyL2ZpbGVzL2FjLXYxLmNybDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFFZuAYBYfPXlPow0N5Ocgf1cNy73MAoGCCqGSM49BAMEA4GLADCBhwJBD6XOKDHsm3C4vg7IR0s7pJEqy1WyBRBd8jNJDyFIHTNTiPwYPPr1yKajmQXFmWIaF0/53nbONb1qoGx69nn0RLsCQgFX/T7v79V4qiF359N2pKQ8LibHxuhCW2XzMEHiASNBFz03Puhk0NwBrhFRjx+q+jWqPBzCAw0D/lSBZzpMj3sDFQ==";

        CertificateToken certificateToken = DSSUtils.loadCertificateFromBase64EncodedString(certB64);
        CertificateToken caCertificate = DSSUtils.loadCertificateFromBase64EncodedString(caCertB64);

        List<CertificateToken> certificateChain = Arrays.asList(certificateToken, caCertificate);

        TrustAnchorVerifier trustAnchorVerifier = TrustAnchorVerifier.createDefaultTrustAnchorVerifier();
        assertFalse(trustAnchorVerifier.isTrustedAtTime(caCertificate, new Date()));
        assertFalse(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, new Date()));

        ValidationPolicy validationPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        trustAnchorVerifier = new TrustAnchorVerifierFactory(validationPolicy).create();

        assertFalse(trustAnchorVerifier.isTrustedAtTime(caCertificate, new Date()));
        assertFalse(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, new Date()));
        assertFalse(trustAnchorVerifier.isTrustedAtTime(caCertificate, new Date(), Context.TIMESTAMP));
        assertFalse(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, new Date(), Context.TIMESTAMP));
        assertFalse(trustAnchorVerifier.isTrustedAtTime(caCertificate, new Date(), Context.REVOCATION));
        assertFalse(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, new Date(), Context.REVOCATION));
        assertFalse(trustAnchorVerifier.isTrustedAtTime(caCertificate, new Date(), Context.SIGNATURE));
        assertFalse(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, new Date(), Context.SIGNATURE));

        LevelConstraint warnConstraint = new LevelConstraint();
        warnConstraint.setLevel(Level.WARN);
        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints().setProspectiveCertificateChain(warnConstraint);
        trustAnchorVerifier = new TrustAnchorVerifierFactory(validationPolicy).create();

        assertFalse(trustAnchorVerifier.isTrustedAtTime(caCertificate, new Date()));
        assertFalse(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, new Date()));
        assertTrue(trustAnchorVerifier.isTrustedAtTime(caCertificate, new Date(), Context.TIMESTAMP));
        assertTrue(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, new Date(), Context.TIMESTAMP));
        assertFalse(trustAnchorVerifier.isTrustedAtTime(caCertificate, new Date(), Context.REVOCATION));
        assertFalse(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, new Date(), Context.REVOCATION));
        assertFalse(trustAnchorVerifier.isTrustedAtTime(caCertificate, new Date(), Context.SIGNATURE));
        assertFalse(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, new Date(), Context.SIGNATURE));

        LevelConstraint failConstraint = new LevelConstraint();
        failConstraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints().setProspectiveCertificateChain(failConstraint);
        validationPolicy.getRevocationConstraints().getBasicSignatureConstraints().setProspectiveCertificateChain(warnConstraint);
        trustAnchorVerifier = new TrustAnchorVerifierFactory(validationPolicy).create();

        assertFalse(trustAnchorVerifier.isTrustedAtTime(caCertificate, new Date()));
        assertFalse(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, new Date()));
        assertFalse(trustAnchorVerifier.isTrustedAtTime(caCertificate, new Date(), Context.TIMESTAMP));
        assertFalse(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, new Date(), Context.TIMESTAMP));
        assertTrue(trustAnchorVerifier.isTrustedAtTime(caCertificate, new Date(), Context.REVOCATION));
        assertTrue(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, new Date(), Context.REVOCATION));
        assertFalse(trustAnchorVerifier.isTrustedAtTime(caCertificate, new Date(), Context.SIGNATURE));
        assertFalse(trustAnchorVerifier.isTrustedCertificateChain(certificateChain, new Date(), Context.SIGNATURE));
    }

}
