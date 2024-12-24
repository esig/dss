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
package eu.europa.esig.dss.spi;

import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.enumerations.GeneralNameType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.extension.AuthorityInformationAccess;
import eu.europa.esig.dss.model.x509.extension.AuthorityKeyIdentifier;
import eu.europa.esig.dss.model.x509.extension.CRLDistributionPoints;
import eu.europa.esig.dss.model.x509.extension.CertificateExtensions;
import eu.europa.esig.dss.model.x509.extension.CertificatePolicies;
import eu.europa.esig.dss.model.x509.extension.CertificatePolicy;
import eu.europa.esig.dss.model.x509.extension.ExtendedKeyUsages;
import eu.europa.esig.dss.model.x509.extension.GeneralName;
import eu.europa.esig.dss.model.x509.extension.GeneralSubtree;
import eu.europa.esig.dss.model.x509.extension.InhibitAnyPolicy;
import eu.europa.esig.dss.model.x509.extension.NameConstraints;
import eu.europa.esig.dss.model.x509.extension.NoRevAvail;
import eu.europa.esig.dss.model.x509.extension.PolicyConstraints;
import eu.europa.esig.dss.model.x509.extension.SubjectAlternativeNames;
import eu.europa.esig.dss.model.x509.extension.SubjectKeyIdentifier;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificateExtensionUtilsTest {

    private static CertificateToken certificateWithAIA;

    private static CertificateToken certificateOCSP;

    @BeforeAll
    static void init() {
        certificateWithAIA = DSSUtils.loadCertificate(new File("src/test/resources/TSP_Certificate_2014.crt"));
        assertNotNull(certificateWithAIA);

        certificateOCSP = DSSUtils.loadCertificateFromBase64EncodedString(
                "MIIEXjCCAkagAwIBAgILBAAAAAABWLd6HkYwDQYJKoZIhvcNAQELBQAwMzELMAkGA1UEBhMCQkUxEzARBgNVBAMTCkNpdGl6ZW4gQ0ExDzANBgNVBAUTBjIwMTYzMTAeFw0xNjEyMTAxMTAwMDBaFw0xODAxMjkxMTAwMDBaMC4xHzAdBgNVBAMTFkJlbGdpdW0gT0NTUCBSZXNwb25kZXIxCzAJBgNVBAYTAkJFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzD0B0c4gBx/wumeE2l/Wcz5FoMSUIuRNIySH2pJ3yfKR/u/FWCOzcrJvDMdmgzR33zGb4/fZel9YlI6xcN08Yd7GkP0/WtbHUhGUPERV76Vvyrk2K/EH/IG2gtxYB+7pkA/ZZycdyjc4IxHzBOiGofP9lDkPD05GSqI7MjVf6sNkZSnHcQSKwkaCGhAshJMjHzShEsSzOgX9kXceBFPTt6Hd2prVmnMTyAwURbQ6gFHbgfxB8JLMya95U6391nGQC66ScH1GhIwd9KSn+yBY0cazJ3nIrc8wd0yGYBgPK78jN3MvAsb1ydfs7kE+Wf95z9oRMiw62Glxh/ksLS/tTQIDAQABo3gwdjAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFBgKRBywCTroyvAErr7p657558Y9MBMGA1UdJQQMMAoGCCsGAQUFBwMJMB8GA1UdIwQYMBaAFM6Al2fQrdlOxJlqgCcikM0RNRCHMA8GCSsGAQUFBzABBQQCBQAwDQYJKoZIhvcNAQELBQADggIBAFuZrqcwt23UiiJdRst66MEBRyKbgPsQM81Uq4FVrAnV8z3l8DDUv+A29KzCPO0GnHSatqA7DNhhMzoBRC42PqCpuvrj8VEWHd43AuPOLaikE04a5tVh6DgW8b00s6Yyf/PuDHCsg2C2MqY71MUR9GcnI7ngR2SyWQGpbsf/wfjujNxEB0+SOwMDTgIAikaueHGZbYkwvlRpL6wm2ENvrE8OvKt7NlNsaWJ4KtQo0QS5Ku+Y2BDA3bX+g8eNLQkaXTycgL4X3MyE5pBOl1OW3KOjJdfyLF+Sii+JKjNf8ZQWk0xvkBEI+nhCzDXhtKAcrkTKlXE25MiUnYoRsXkXgrzYftxAMxvFOXJji/hnX5Fe/3SBAHaE+jU6yC5nk6Q9ERii8mL0nHouMlZWSiAuXtlZDFrzwtLD2ITBECe4X60BDQfb/caO2u3HcWoG1AOvGxfQB0cMmP2njCdDf8UOqryiyky4t7Jj3ghOvETjWlwMw5ObhZ8yj8p6qFAt7+EVJfpUc1gDAolS/hJoLzohbL5LnCAnUAWsFpvG3qW1ky+X0MePXi6q/boqj2tcC4IDdsYS6RHPBvzl5+yLDccrGx1s/7vQYTMNyX0dYZzuxFZxx0bttWfjqLz3hFHlAEVmLCyUkSz761CbaT9u/G4tPP4Q8ApFfSskPI57lbLWIcwP");
        assertNotNull(certificateOCSP);
    }

    @Test
    void getCertificatePolicies() {
        CertificatePolicies certificatePolicies = CertificateExtensionsUtils.getCertificatePolicies(certificateWithAIA);
        assertNotNull(certificatePolicies);
        List<CertificatePolicy> policyIdentifiers = certificatePolicies.getPolicyList();
        assertEquals(2, policyIdentifiers.size());
        CertificatePolicy certificatePolicy1 = policyIdentifiers.get(0);
        assertEquals("1.3.171.1.1.10.8.1", certificatePolicy1.getOid());
        assertEquals("https://repository.luxtrust.lu", certificatePolicy1.getCpsUrl());

        CertificatePolicy certificatePolicy2 = policyIdentifiers.get(1);
        assertEquals("0.4.0.2042.1.3", certificatePolicy2.getOid());
        assertNull(certificatePolicy2.getCpsUrl());
    }

    @Test
    void getSKI() {
        SubjectKeyIdentifier subjectKeyIdentifier = CertificateExtensionsUtils.getSubjectKeyIdentifier(certificateWithAIA);
        assertNotNull(subjectKeyIdentifier);
        byte[] ski = subjectKeyIdentifier.getSki();
        assertEquals("4c4c4cfcacace6bb", Utils.toHex(ski));

        CertificateToken certNoSKIextension = DSSUtils.loadCertificateFromBase64EncodedString(
                "MIICaDCCAdSgAwIBAgIDDIOqMAoGBiskAwMBAgUAMG8xCzAJBgNVBAYTAkRFMT0wOwYDVQQKFDRSZWd1bGllcnVuZ3NiZWjIb3JkZSBmyHVyIFRlbGVrb21tdW5pa2F0aW9uIHVuZCBQb3N0MSEwDAYHAoIGAQoHFBMBMTARBgNVBAMUCjVSLUNBIDE6UE4wIhgPMjAwMDAzMjIwODU1NTFaGA8yMDA1MDMyMjA4NTU1MVowbzELMAkGA1UEBhMCREUxPTA7BgNVBAoUNFJlZ3VsaWVydW5nc2JlaMhvcmRlIGbIdXIgVGVsZWtvbW11bmlrYXRpb24gdW5kIFBvc3QxITAMBgcCggYBCgcUEwExMBEGA1UEAxQKNVItQ0EgMTpQTjCBoTANBgkqhkiG9w0BAQEFAAOBjwAwgYsCgYEAih5BUycfBpqKhU8RDsaSvV5AtzWeXQRColL9CH3t0DKnhjKAlJ8iccFtJNv+d3bh8bb9sh0maRSo647xP7hsHTjKgTE4zM5BYNfXvST79OtcMgAzrnDiGjQIIWv8xbfV1MqxxdtZJygrwzRMb9jGCAGoJEymoyzAMNG7tSdBWnUCBQDAAAABoxIwEDAOBgNVHQ8BAf8EBAMCAQYwCgYGKyQDAwECBQADgYEAOaK8ihVSBUcL2IdVBxZYYUKwMz5m7H3zqhN8W9w+iafWudH6b+aahkbENEwzg3C3v5g8nze7v7ssacQze657LHjP+e7ksUDIgcS4R1pU2eN16bjSP/qGPF3rhrIEHoK5nJULkjkZYTtNiOvmQ/+G70TXDi3Os/TwLlWRvu+7YLM=");
        assertNull(CertificateExtensionsUtils.getSubjectKeyIdentifier(certNoSKIextension));

        CertificateToken c1 = DSSUtils.loadCertificateFromBase64EncodedString(
                "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");
        CertificateToken c2 = DSSUtils.loadCertificateFromBase64EncodedString(
                "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");

        subjectKeyIdentifier = CertificateExtensionsUtils.getSubjectKeyIdentifier(c1);
        assertNotNull(subjectKeyIdentifier);
        byte[] skiC1 = subjectKeyIdentifier.getSki();
        assertTrue(Utils.isArrayNotEmpty(skiC1));

        subjectKeyIdentifier = CertificateExtensionsUtils.getSubjectKeyIdentifier(c2);
        assertNotNull(subjectKeyIdentifier);
        byte[] skiC2 = subjectKeyIdentifier.getSki();
        assertTrue(Utils.isArrayNotEmpty(skiC2));

        assertFalse(Arrays.equals(skiC1, skiC2));

        byte[] encodedPKC1 = c1.getPublicKey().getEncoded();
        byte[] encodedPKC2 = c2.getPublicKey().getEncoded();

        assertArrayEquals(encodedPKC1, encodedPKC2);
    }

    @Test
    void getAuthorityKeyIdentifier() {
        CertificateToken cert = DSSUtils.loadCertificateFromBase64EncodedString(
                "MIICaDCCAdSgAwIBAgIDDIOqMAoGBiskAwMBAgUAMG8xCzAJBgNVBAYTAkRFMT0wOwYDVQQKFDRSZWd1bGllcnVuZ3NiZWjIb3JkZSBmyHVyIFRlbGVrb21tdW5pa2F0aW9uIHVuZCBQb3N0MSEwDAYHAoIGAQoHFBMBMTARBgNVBAMUCjVSLUNBIDE6UE4wIhgPMjAwMDAzMjIwODU1NTFaGA8yMDA1MDMyMjA4NTU1MVowbzELMAkGA1UEBhMCREUxPTA7BgNVBAoUNFJlZ3VsaWVydW5nc2JlaMhvcmRlIGbIdXIgVGVsZWtvbW11bmlrYXRpb24gdW5kIFBvc3QxITAMBgcCggYBCgcUEwExMBEGA1UEAxQKNVItQ0EgMTpQTjCBoTANBgkqhkiG9w0BAQEFAAOBjwAwgYsCgYEAih5BUycfBpqKhU8RDsaSvV5AtzWeXQRColL9CH3t0DKnhjKAlJ8iccFtJNv+d3bh8bb9sh0maRSo647xP7hsHTjKgTE4zM5BYNfXvST79OtcMgAzrnDiGjQIIWv8xbfV1MqxxdtZJygrwzRMb9jGCAGoJEymoyzAMNG7tSdBWnUCBQDAAAABoxIwEDAOBgNVHQ8BAf8EBAMCAQYwCgYGKyQDAwECBQADgYEAOaK8ihVSBUcL2IdVBxZYYUKwMz5m7H3zqhN8W9w+iafWudH6b+aahkbENEwzg3C3v5g8nze7v7ssacQze657LHjP+e7ksUDIgcS4R1pU2eN16bjSP/qGPF3rhrIEHoK5nJULkjkZYTtNiOvmQ/+G70TXDi3Os/TwLlWRvu+7YLM=");
        assertNull(CertificateExtensionsUtils.getAuthorityKeyIdentifier(cert));
        assertTrue(cert.isSelfSigned());

        AuthorityKeyIdentifier aKI = CertificateExtensionsUtils.getAuthorityKeyIdentifier(certificateWithAIA);
        assertNotNull(aKI);
        assertTrue(Utils.isArrayNotEmpty(aKI.getKeyIdentifier()));
        assertFalse(Utils.isArrayNotEmpty(aKI.getAuthorityCertIssuerSerial()));
        AuthorityKeyIdentifier aKI2 = CertificateExtensionsUtils.getAuthorityKeyIdentifier(certificateOCSP);
        assertNotNull(aKI2);
        assertTrue(Utils.isArrayNotEmpty(aKI2.getKeyIdentifier()));
        assertFalse(Utils.isArrayNotEmpty(aKI2.getAuthorityCertIssuerSerial()));
    }

    @Test
    void getAccessLocation() {
        CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
        AuthorityInformationAccess aia = CertificateExtensionsUtils.getAuthorityInformationAccess(certificate);
        assertNotNull(aia);
        List<String> ocspAccessLocations = aia.getOcsp();
        assertEquals(1, Utils.collectionSize(ocspAccessLocations));
        assertEquals("http://ocsp.luxtrust.lu", ocspAccessLocations.get(0));
        assertEquals(ocspAccessLocations, CertificateExtensionsUtils.getOCSPAccessUrls(certificate));
    }

    @Test
    void getCAAccessLocations() {
        CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
        AuthorityInformationAccess aia = CertificateExtensionsUtils.getAuthorityInformationAccess(certificate);
        assertNotNull(aia);
        List<String> caLocations = aia.getCaIssuers();
        assertEquals(1, Utils.collectionSize(caLocations));
        assertEquals("http://ca.luxtrust.lu/LTQCA.crt", caLocations.get(0));
        assertEquals(caLocations, CertificateExtensionsUtils.getCAIssuersAccessUrls(certificate));
    }

    @Test
    void getCrlUrls() {
        CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
        CRLDistributionPoints crlDistributionPoints = CertificateExtensionsUtils.getCRLDistributionPoints(certificate);
        assertNotNull(crlDistributionPoints);
        List<String> crlUrls = crlDistributionPoints.getCrlUrls();
        assertEquals(1, Utils.collectionSize(crlUrls));
        assertEquals("http://crl.luxtrust.lu/LTQCA.crl", crlUrls.get(0));
        assertEquals(crlUrls, CertificateExtensionsUtils.getCRLAccessUrls(certificate));
    }

    @Test
    void isOCSPSigning() {
        ExtendedKeyUsages extendedKeyUsage = CertificateExtensionsUtils.getExtendedKeyUsage(certificateOCSP);
        assertNotNull(extendedKeyUsage);
        assertTrue(extendedKeyUsage.getOids().contains(ExtendedKeyUsage.OCSP_SIGNING.getOid()));

        extendedKeyUsage = CertificateExtensionsUtils.getExtendedKeyUsage(certificateWithAIA);
        assertNotNull(extendedKeyUsage);
        assertFalse(extendedKeyUsage.getOids().contains(ExtendedKeyUsage.OCSP_SIGNING.getOid()));
    }

    @Test
    void hasIdPkixOcspNoCheckExtension() {
        assertTrue(CertificateExtensionsUtils.hasOcspNoCheckExtension(certificateOCSP));
        assertFalse(CertificateExtensionsUtils.hasOcspNoCheckExtension(certificateWithAIA));
    }

    @Test
    void hasValAssuredShortTermCertsExtension() {
        CertificateToken shortTermCertificate = DSSUtils.loadCertificateFromBase64EncodedString("MIIDJjCCAg6gAwIBAgIIMMSTGSdLPxQwDQYJKoZIhvcNAQENBQAwKDEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczELMAkGA1UEBhMCTFUwHhcNMjEwNzAxMTAwMTI5WhcNMjEwNzAxMTAwNjI5WjA2MQwwCgYDVQQDDANBIGExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxCzAJBgNVBAYTAkxVMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsW0yfJBqh9CtbfOtsZcEAEvzzfPusdhZNv0JSq8frKGMqJwTgjnkMJd9D3sEHUBJP0ryAmK9L5S+lWOGDhdYcE8K00k3hZSHyrOdRblB0SZhtXIgeGD7ESdTU9xPCf4Ze7xSI08zlk9NmTaj5Xqfyako8sxHAQapdXw8kfG0Ol6UhfMg7MjN8/wZrIVUYZzBQP3RFKHFQIms+pxfWxvETsynn/n2rOjuAsV0aTWGUAeWJRFJxKLSTrHQiQULVS1MHIIkdbQZxMA+Jn3dXwVdJLX/JRSvEOBqGRrvGQtYN2vNdrJlNHP0WGcSAddweWs7Ar+Pp7Qm/HEQF5+EOPUQDQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCBsAwIwYIKwYBBQUHAQMEFzAVMBMGBgQAjkYBBjAJBgcEAI5GAQYBMA0GBwQAi+xJAgEEAgUAMA0GCSqGSIb3DQEBDQUAA4IBAQBAYj8mdKsj/mMoM4HXL/w+xeK0iM55eGyBNprwxECoCH8ZCgVrVTb3eKttTXYrXjk3Yqpg3amkm7aV94iXJ0qLER/2C9lHLv6h1CoxYCdevAUSVOIzF0SJj54dxrwDQ7uTFXRe2etOg+hmEhj3OBpd/5vMfdIViYHtpPoCyZoQyGLztUt1k8/JvBe91UGAEnWx0nvokehkTgueq7dsTjBit4dlCmfmIzQUUWCgNpe1S1nEb0B/BCXaqPRhYx1//2T/5gR1lKe36HHp5rUURKT8NsS76lfxdor9Ag3mVmsw1NcVtDiFo0molO84+B53yqRP2wCU7MtfKfCX9CocgVNF");
        assertTrue(CertificateExtensionsUtils.hasValAssuredShortTermCertsExtension(shortTermCertificate));
        assertFalse(CertificateExtensionsUtils.hasValAssuredShortTermCertsExtension(certificateOCSP));
    }

    @Test
    void readOCSPAccessLocationsAndStopOnceLoopDetected() {
        CertificateToken caTokenA = DSSUtils.loadCertificateFromBase64EncodedString("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");
        CertificateToken caTokenB = DSSUtils.loadCertificateFromBase64EncodedString("MIIGezCCBWOgAwIBAgIUe2/+Jhp5ZUPNx4jhX5D14+zmm/QwDQYJKoZIhvcNAQELBQAwVzELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEfMB0GA1UEAxMWRmVkZXJhbCBCcmlkZ2UgQ0EgMjAxNjAeFw0xNjExMDgxODE0MzZaFw0xOTExMDgxODE0MzZaMFkxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDTALBgNVBAsTBEZQS0kxITAfBgNVBAMTGEZlZGVyYWwgQ29tbW9uIFBvbGljeSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANh1+zUWNFpBv1qvXDAEFByteES16ibqdWHHzTZ5+HzYvSlRZlkh43mr1Hi+sC2wodWyNRYj0Mwevg7oq9zDydYS16dyaBgxuBcisj5+ughtxv3RWCxpoAPwKqP2PyElPd+3MsWOJ7MjpeBSs12W6bC4xcWfu8WgboJAu8UnBTZJ1iYnaQw0j88neioKo0FfjR0DhoMV4FXBxZgsnuwactxIwT75hNKEgsEbw3Q2t7nHNjJ6+DK20DauIhgxjFBzIZ7+gzswiCTj6cF+3u2Yxx+SEIqfW2IvnaS81YVvOv3JU6cgS6rbIKshTh0NTuaYheWrEUddnT/EI8DjFAZu/p0CAwEAAaOCAzswggM3MA8GA1UdEwEB/wQFMAMBAf8wggFBBgNVHSAEggE4MIIBNDAMBgpghkgBZQMCAQMNMAwGCmCGSAFlAwIBAwEwDAYKYIZIAWUDAgEDAjAMBgpghkgBZQMCAQMOMAwGCmCGSAFlAwIBAw8wDAYKYIZIAWUDAgEDETAMBgpghkgBZQMCAQMSMAwGCmCGSAFlAwIBAxMwDAYKYIZIAWUDAgEDFDAMBgpghkgBZQMCAQMDMAwGCmCGSAFlAwIBAwwwDAYKYIZIAWUDAgEDBDAMBgpghkgBZQMCAQMlMAwGCmCGSAFlAwIBAyYwDAYKYIZIAWUDAgEDBjAMBgpghkgBZQMCAQMHMAwGCmCGSAFlAwIBAwgwDAYKYIZIAWUDAgEDJDAMBgpghkgBZQMCAQMQMAwGCmCGSAFlAwIBAycwDAYKYIZIAWUDAgEDKDAMBgpghkgBZQMCAQMpMFMGCCsGAQUFBwEBBEcwRTBDBggrBgEFBQcwAoY3aHR0cDovL2h0dHAuZnBraS5nb3YvYnJpZGdlL2NhQ2VydHNJc3N1ZWRUb2ZiY2EyMDE2LnA3YzCBjQYDVR0hBIGFMIGCMBgGCmCGSAFlAwIBAwMGCmCGSAFlAwIBAwYwGAYKYIZIAWUDAgEDBAYKYIZIAWUDAgEDEDAYBgpghkgBZQMCAQMMBgpghkgBZQMCAQMHMBgGCmCGSAFlAwIBAyUGCmCGSAFlAwIBAwgwGAYKYIZIAWUDAgEDJgYKYIZIAWUDAgEDJDBPBggrBgEFBQcBCwRDMEEwPwYIKwYBBQUHMAWGM2h0dHA6Ly9odHRwLmZwa2kuZ292L2ZjcGNhL2NhQ2VydHNJc3N1ZWRCeWZjcGNhLnA3YzAPBgNVHSQBAf8EBTADgQEBMA0GA1UdNgEB/wQDAgEAMA4GA1UdDwEB/wQEAwIBBjAfBgNVHSMEGDAWgBQjsLN9FlTUAlZ26zq+qWsvQ3soFjA5BgNVHR8EMjAwMC6gLKAqhihodHRwOi8vaHR0cC5mcGtpLmdvdi9icmlkZ2UvZmJjYTIwMTYuY3JsMB0GA1UdDgQWBBStDHp1XOXzmMR5mA6sKP2X9OcC/DANBgkqhkiG9w0BAQsFAAOCAQEAZ8jRNy3bbIg6T5NCO4nGRtfLOCNvvRX/G6nz8Ax7FG3/xrZQy9jwDymdp0wQTJ1vKhtpQ0Nv0BxU3zw1OzujKoD6y7mb5EsunGXVi7Rltw1LJVZCaXC40DfDVEqx4hVd0JdoFluBBYs8XZEdve1sobkEAfNUhn5LMCklqGb55jSPSdXDN5HJ3t3vJ5xjXbeWbsTAh0Ta3Z7pZA5osMKx39VwXItWYyaBfCxOLRb9Nu+wEqrxpld83pGEJpzvR7SWfBirfVYa3E1kHizjTsM1GY7pjtHGwM2iYgJUuJwW32HHPxwlMwAr4zxG5ev/VUxGhmZw9bbkbLvmLvXXEGb6BQ==");
        assertTrue(caTokenA.isSignedBy(caTokenB));
        assertTrue(caTokenB.isSignedBy(caTokenA));
        AuthorityInformationAccess aia = CertificateExtensionsUtils.getAuthorityInformationAccess(caTokenA);
        assertNotNull(aia);
        List<String> ocspAccessLocations = aia.getOcsp();
        assertNotNull(ocspAccessLocations);
        assertEquals(ocspAccessLocations, CertificateExtensionsUtils.getOCSPAccessUrls(caTokenA));
    }

    @Test
    void getSubjectAlternativeNames() {
        CertificateToken cert = DSSUtils.loadCertificateFromBase64EncodedString(
                "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");
        assertNotNull(cert);

        SubjectAlternativeNames subjectAlternativeNamesExtension = CertificateExtensionsUtils.getSubjectAlternativeNames(cert);
        assertNotNull(subjectAlternativeNamesExtension);
        List<GeneralName> subjectAlternativeNames = subjectAlternativeNamesExtension.getGeneralNames();
        assertNotNull(subjectAlternativeNames);
        assertEquals(1, Utils.collectionSize(subjectAlternativeNames));
        assertEquals(GeneralNameType.DNS_NAME, subjectAlternativeNames.get(0).getGeneralNameType());
        assertEquals("creditas.cz", subjectAlternativeNames.get(0).getValue());

        cert = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
        assertNotNull(cert);

        subjectAlternativeNamesExtension = CertificateExtensionsUtils.getSubjectAlternativeNames(cert);
        assertNotNull(subjectAlternativeNamesExtension);
        subjectAlternativeNames = subjectAlternativeNamesExtension.getGeneralNames();
        assertNotNull(subjectAlternativeNames);
        assertEquals(0, Utils.collectionSize(subjectAlternativeNames));

        cert = DSSUtils.loadCertificateFromBase64EncodedString(
                "MIIFbTCCA1WgAwIBAgIIZuEvyPq8dbwwDQYJKoZIhvcNAQELBQAwSDELMAkGA1UEBhMCRVMxEjAQBgNVBAcTCUJhcmNlbG9uYTEMMAoGA1UEChMDVVBDMRcwFQYDVQQDDA40LjIuMS4xMF8wNF9DQTAeFw0yMzAzMjkyMjUyMDBaFw0yNDAzMjkyMjUyMDBaMEkxCzAJBgNVBAYTAkVTMRIwEAYDVQQHEwlCYXJjZWxvbmExDDAKBgNVBAoTA1VQQzEYMBYGA1UEAwwPNC4yLjEuMTBfMDRfRUUyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuyY+QqQLt/4v3tfaOY0ICo8xLXL2/u2Vxpn5AvoM0U8m/D7sgSTJ0IXiXuOnwoWk+CDABi9VWDYZaj6xHFuTw+zZwHlX8OjjalHD/eWoV8Y0e1XEdqoW3pBxEbZ+QfvxdLyR+hkWSAFIDC18v/U441FaqjL6CejIcqh5Ke+fYxhtVRIt2PUfLRg2NWzmzY4nUkzD5cN0Q/StK7CraGQcyWfzOTbJVTYx+2GZLxNhfkceZoHhwNTqHN+UNng+/JymOgjZon9IQOuo3ItChAMGY+e1pt/DA2kppvgobEYkbnAp/Vtg2nammQKqXmOTMW10uHIBmVEeqK60cDmPbFIr5wsviOtnVrlMQ3qA3m2GkLdDYV4x5bZucCS8nlL2R4mwh2JFn5O4PJLXBA5yrL7Q3ZGfGjtus1tF65gjNV6/jyuo81t56tnclVqYlo1yIrZ4mSjRE4pWwtWaGjZ2EUb94RUCafFozAfgYtPDJMm6c38yVWpiCLukbRqXKc03fuJCUkvJiSxe6QrEGcui7cW8K6YXvwF6hH+Gif28vkpF5/nxgG+xemJ9DKHmcCD+/oDL+yWoz9IFKTUXj5bvwaQkscK2RlCCIZRTHn1I4CnwOLZgI+hpJORulYPuSmRgT2sYJJYJLutO1efv5O0vXkeTIX5m7g/rtaZtAAHljdU/TDkCAwEAAaNaMFgwVgYDVR0RBE8wTaRLMEkxCzAJBgNVBAYTAkVTMRIwEAYDVQQHEwlCYXJjZWxvbmExDDAKBgNVBAoTA1VQQzEYMBYGA1UEAwwPNC4yLjEuMTBfMDRfRUUyMA0GCSqGSIb3DQEBCwUAA4ICAQCgnxjBJfGH/xbBcVGSAHx3fGvkSOptpzCuSLTJXS4xPM/Ow4iE5a8FTaoxBrxUa9wR40intTBhVCT0t9i9aFJY7LYi+bhs/1Ul26k6Ch2KcCQdlWHRpngS4va9BFkYbjDok2g2cHzTByL2mOEOGb7n75rgDr0ftuXwmLu6tJeuzGCy/MhhS9kFSj+Semc7QZtRkAxhUrlTcJmMdGAg2/JHsFIm3fcJX+khjTf13aQfDH95UGYr1DDqOXBe/xmAWf0vpmdU7FPMo9flcYx+l+6hMwQlyk1n6xmtdWDvnhwCWxqKihS7PS7mAmJ6W4yiVJjDFbZ1jKfEqdYgyqMYXf9x7kAI1S3Ci0JZg7E227ilF9nNrAEBZLZJE5HL190tRPvbsU5Lsk+tMrBdunYn2h0HqhMdwLY9rEGiD/KguG6uCkCbfi+W0GtxMS7SiXiL6DPw8Nb4WyH+JyRT2vP05RSRnpq201dD+dkyqQAz3FXZyhtn5WHcSStmz3wqwEw9fASumWO/CzOprqSb7XIToH9f7/8BekAhWBVi2c+yNX3JOXxJGOQwht3Fsc2Yc/pxMBaX+TzblRsA7jkIRsmiS+GQYiOXEzRypCGus2rQIhZOBcn/keJdIFbGEyaJg0/p96bdO01krcd5xAO3w2xpSc4ZWTjFFGFmIYCiXFGwW7OaXg==");
        assertNotNull(cert);

        subjectAlternativeNamesExtension = CertificateExtensionsUtils.getSubjectAlternativeNames(cert);
        assertNotNull(subjectAlternativeNamesExtension);
        subjectAlternativeNames = subjectAlternativeNamesExtension.getGeneralNames();
        assertNotNull(subjectAlternativeNames);
        assertEquals(1, Utils.collectionSize(subjectAlternativeNames));
        assertEquals(GeneralNameType.DIRECTORY_NAME, subjectAlternativeNames.get(0).getGeneralNameType());
        assertEquals("CN=4.2.1.10_04_EE2,O=UPC,L=Barcelona,C=ES", subjectAlternativeNames.get(0).getValue());

        cert = DSSUtils.loadCertificateFromBase64EncodedString(
                "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=");
        assertNotNull(cert);

        subjectAlternativeNamesExtension = CertificateExtensionsUtils.getSubjectAlternativeNames(cert);
        assertNotNull(subjectAlternativeNamesExtension);
        subjectAlternativeNames = subjectAlternativeNamesExtension.getGeneralNames();
        assertNotNull(subjectAlternativeNames);
        assertEquals(2, Utils.collectionSize(subjectAlternativeNames));
        assertEquals(GeneralNameType.RFC822_NAME, subjectAlternativeNames.get(0).getGeneralNameType());
        assertEquals("bWlndWVsYW5nZWwubmFmcmlhQHNlYXAubWluaGFwLmVz", Utils.toBase64(subjectAlternativeNames.get(0).getValue().getBytes()));
        assertEquals(GeneralNameType.DIRECTORY_NAME, subjectAlternativeNames.get(1).getGeneralNameType());
        assertEquals("1.3.6.1.4.1.5734.1.1=#0c0c4d494755454c20414e47454c,1.3.6.1.4.1.5734.1.2=#0c064e4146524941,1.3.6.1.4.1.5734.1.3=#0c094c4153204845524153,1.3.6.1.4.1.5734.1.4=#0c09373238373432363858", subjectAlternativeNames.get(1).getValue());

        cert = DSSUtils.loadCertificateFromBase64EncodedString(
                "MIIFQzCCAyugAwIBAgIIYgrumZXsDzcwDQYJKoZIhvcNAQELBQAwSjELMAkGA1UEBhMCRVMxEjAQBgNVBAcTCUJhcmNlbG9uYTEMMAoGA1UEChMDVVBDMRkwFwYDVQQDDBA0LjIuMS4xMF8xMV9DQTExMB4XDTIzMDQwMTIxMzkwMFoXDTI0MDQwMTIxMzkwMFowTTELMAkGA1UEBhMCRVMxEjAQBgNVBAcTCUJhcmNlbG9uYTEMMAoGA1UEChMDVVBDMRwwGgYDVQQDDBM0LjIuMS4xMF8xMV9DQTExX0VFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmpYkSbMZA7RighHHZD7TMeE3ZO/nbHnorUJotxQ0CUcLDpmF7EfC66IfunaFKas/q/LiU+xm+GCnqqO13nEBTZOOyCbq0w3+zl0e1iqPfaZDOFOLXS/z14Z29e56LFJPKKZS0na1/D0zcG8s8tYaQsldz6kgIONtKNSz5Tnf6Q5yohLdImL6KcP1JsfzP/GCMgnJb4UbcCtqtWRNmOCZcUtD37tFyvEIkDjFHa65WoPy6IbtGS7Hawx4ZZZLCCb3QOi5bmK1ZZL8zHllqnHWM85Fc6k/0R6en47/MlclDSci/OD+1IyBzAcru6HOcN7d96J/6QapXVUokmoRMqSpgeF8qi2d4phXzYipTDkvyZ+f0oTEb7MyH6zviFm+WTLlDD32OEoq1dwzdaup2NUp4MEKO+T3B4hn589io/FMHr5WpmbN/gxg0hgC2ONz/oX3DtSTClw8CEunbDJ5GVtQcIrI0ZBbAnRCi5WicXtrZBgbO0A5BeMitsuo3WNCkXLfyIO6/c0fFlEXWihrQ/OVcLHIHKxsiWcCRbEQzVRGiJoc3rx39AEtqwexn1Gfd33CKTGlDZMtpzhP96yxj1c+RwsOBZEq5ecCQTMFrCwfP9BbMJf9BdmUI6eGUxDsEUVUHiYESeNuMPUkwQMtVbdw26JvunRuwFGepODBlkCB73kCAwEAAaMqMCgwCwYDVR0PBAQDAgeAMBkGA1UdEQEB/wQPMA2GC3d3dy51cGMyLmVzMA0GCSqGSIb3DQEBCwUAA4ICAQAOSWXjnOjKJsBoQKSm8YlL69wBEGe2Xa5TWKxEddXBwoM+wwXZRjmmbE92Ebdve1a9RPDHkHmQ+9+rPUA73hV+KXOB0yLSyn5l+Z0+9RLSwDMXm+UQy5UtsdFIxGHapTu1R6PkvCkbvrGM58pjM8XmcAEAFveM8DBnDI17z1RKfmy63eyltb5OTUZGzVBWD/ZTp8rm2X9wZSUhuOp57Mm5OEilBtXKnHYoiqHbnrdHvKM7ea15WzE7AvF4STmT+zGd5EMkJGN+pmsyxH+HoOWqI6/OxTqvn/pcrKjLt9Eo8VIirEGcHUSdOfNlVivRvb6j2Bpt1hI0m9+B7pmolbSepkCVAvUxnMDZ7ufvNEsynm4avavj+Ifj1Xz8DLge0YHR/ff6oF5XdiBn74GuB9m4/m8LJuBYx+64UUeUkUNjF6cKd8MfHUEevHPvLgsb7/8pVhvG+Su2T+xP6yyHsMcUbpJkp/110AC1ZAqBV7Ne854Qk/3oc2BcLHWQKNHuTSqZcHFQnpeFtOfAInlhJetiVn38cn64gGEdlKxj8xOH/UPNfckZvZoEIoeFWnlzjEYhYQBpfXAWl9yW9Wk6Fb4AXpBKwiaxou027qE6XjJTnTm+APqL4IekI3Y4p+Yf9MlMjyC5cxUeNOeeq0V37DcIFessG3dU1DV50PiWEee8fw==");
        assertNotNull(cert);

        subjectAlternativeNamesExtension = CertificateExtensionsUtils.getSubjectAlternativeNames(cert);
        assertNotNull(subjectAlternativeNamesExtension);
        subjectAlternativeNames = subjectAlternativeNamesExtension.getGeneralNames();
        assertNotNull(subjectAlternativeNames);
        assertEquals(1, Utils.collectionSize(subjectAlternativeNames));
        assertEquals(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER, subjectAlternativeNames.get(0).getGeneralNameType());
        assertEquals("www.upc2.es", subjectAlternativeNames.get(0).getValue());

        cert = DSSUtils.loadCertificateFromBase64EncodedString(
                "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");
        assertNotNull(cert);

        subjectAlternativeNamesExtension = CertificateExtensionsUtils.getSubjectAlternativeNames(cert);
        assertNotNull(subjectAlternativeNamesExtension);
        subjectAlternativeNames = subjectAlternativeNamesExtension.getGeneralNames();
        assertNotNull(subjectAlternativeNames);
        assertEquals(2, Utils.collectionSize(subjectAlternativeNames));
        assertEquals(GeneralNameType.OTHER_NAME, subjectAlternativeNames.get(0).getGeneralNameType());
        assertEquals("#a022060a2b060104018237140203a0140c12636f6e74616374406164722e676f762e726f", subjectAlternativeNames.get(0).getValue());
        assertEquals(GeneralNameType.RFC822_NAME, subjectAlternativeNames.get(1).getGeneralNameType());
        assertEquals("Y29udGFjdEBhZHIuZ292LnJv", Utils.toBase64(subjectAlternativeNames.get(1).getValue().getBytes()));
    }

    @Test
    void getPolicyConstraints() {
        CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/sk_ca.cer"));
        PolicyConstraints policyConstraints = CertificateExtensionsUtils.getPolicyConstraints(certificate);
        assertNotNull(policyConstraints);
        assertEquals(0, policyConstraints.getRequireExplicitPolicy());
        assertEquals(-1, policyConstraints.getInhibitPolicyMapping());

        CertificateExtensions certificateExtensions = CertificateExtensionsUtils.getCertificateExtensions(certificate);
        PolicyConstraints policyConstraintsExt = certificateExtensions.getPolicyConstraints();
        assertNotNull(policyConstraintsExt);
        assertEquals(0, policyConstraintsExt.getRequireExplicitPolicy());
        assertEquals(-1, policyConstraintsExt.getInhibitPolicyMapping());
    }

    @Test
    void getPolicyConstraintsTwo() {
        CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(
                "MIIClDCCAf2gAwIBAgIBNzANBgkqhkiG9w0BAQUFADBAMQswCQYDVQQGEwJVUzEaMBgGA1UEChMRVGVz\n" +
                "dCBDZXJ0aWZpY2F0ZXMxFTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw0wMTA0MTkxNDU3MjBaFw0xMTA0\n" +
                "MTkxNDU3MjBaMEwxCzAJBgNVBAYTAlVTMRowGAYDVQQKExFUZXN0IENlcnRpZmljYXRlczEhMB8GA1UE\n" +
                "AxMYaW5oaWJpdFBvbGljeU1hcHBpbmcwIENBMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDQIzx8\n" +
                "7J8x9DkeOhXlBG/eAUo6B99wk9uPjSwrZ7f+CXzaECXTCOk88n35mahe/lgpBbr8ujs9D6bCgS+AVciy\n" +
                "qJAtZFW45FX6xjb6fcLzebF4HTOpBYVxkqlJ9nLLCkaBHMIq1U5jR8jDZhgTnMBvNm0yBdNFo6Lh6A5d\n" +
                "+Gr5jwIDAQABo4GRMIGOMB8GA1UdIwQYMBaAFPts1C2Bnsonep4NsDzqmryH/0nqMB0GA1UdDgQWBBRs\n" +
                "6ccKAUJAQfXzcI7u4dFSXtc3WjAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATAB\n" +
                "MA8GA1UdEwEB/wQFMAMBAf8wEgYDVR0kAQH/BAgwBoABAIEBADANBgkqhkiG9w0BAQUFAAOBgQDR8om4\n" +
                "2wMsHX434zvF/Yl3Lm4GBdFmFWIiRNpqH5iS8X1lGbi1pEAgm37Pvvobd5tcsZd2tsz0/DOTvntZhUdX\n" +
                "5rmvN4x0i3JUXb9bOPMDs2iJs5oFF6IqTSk9wJXUwsPy3ltGGWpU817s4uj8HU3tffkyOyc7j1u3l8x2\n" +
                "LJWPvA==");
        PolicyConstraints policyConstraints = CertificateExtensionsUtils.getPolicyConstraints(certificate);
        assertNotNull(policyConstraints);
        assertEquals(0, policyConstraints.getRequireExplicitPolicy());
        assertEquals(0, policyConstraints.getInhibitPolicyMapping());
    }

    @Test
    void getInhibitAnyPolicy() {
        CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(
                "MIICmTCCAgKgAwIBAgIBOzANBgkqhkiG9w0BAQUFADBAMQswCQYDVQQGEwJVUzEaMBgGA1UEChMRVGVz\n" +
                "dCBDZXJ0aWZpY2F0ZXMxFTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw0wMTA0MTkxNDU3MjBaFw0xMTA0\n" +
                "MTkxNDU3MjBaMEgxCzAJBgNVBAYTAlVTMRowGAYDVQQKExFUZXN0IENlcnRpZmljYXRlczEdMBsGA1UE\n" +
                "AxMUaW5oaWJpdEFueVBvbGljeTAgQ0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALXCzoaXAEbX\n" +
                "pgMPDk3SCu2nzrt+I18MsI4lg/0oLjQAgPsD0np8LOGHMzo3UBtfJtpV0BXCc+E++Ni+ehXFWfA4BXjF\n" +
                "c3GdUdJmn7y3F9X7XSIauTE1GSYR2+bMW/IRbmjpMDzldmRsWNb40N+jWAxw1h+YN61Pv0MD7Ef2ds0N\n" +
                "AgMBAAGjgZowgZcwHwYDVR0jBBgwFoAU+2zULYGeyid6ng2wPOqavIf/SeowHQYDVR0OBBYEFJ1AmGAI\n" +
                "5sj9XNHYLwvqAOwaRQbPMA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDwYD\n" +
                "VR0TAQH/BAUwAwEB/zAMBgNVHSQEBTADgAEAMA0GA1UdNgEB/wQDAgEAMA0GCSqGSIb3DQEBBQUAA4GB\n" +
                "ALhhUDb9VolIM2bKpbpat4dNjGrkOmVT/HvGBl+FGwSXa7MjcLgZ3WygZ9gil3l7X+wL7lM9zKpXljV5\n" +
                "WNpX+58RclQ2kK7Yk4qcY0tpPEUn8R4/9yg64Nferl/2gn9W79ODU3BiBFF/GiAJJ4SiwvLWl/JnPDoQ\n" +
                "uJv67IS24+Oa");
        InhibitAnyPolicy inhibitAnyPolicy = CertificateExtensionsUtils.getInhibitAnyPolicy(certificate);
        assertNotNull(inhibitAnyPolicy);
        assertEquals(0, inhibitAnyPolicy.getValue());

        CertificateExtensions certificateExtensions = CertificateExtensionsUtils.getCertificateExtensions(certificate);
        InhibitAnyPolicy inhibitAnyPolicyExt = certificateExtensions.getInhibitAnyPolicy();
        assertNotNull(inhibitAnyPolicyExt);
        assertEquals(0, inhibitAnyPolicyExt.getValue());
    }

    @Test
    void getNameConstraintsPermittedSubtrees() {
        CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(
                "MIIC2TCCAkKgAwIBAgIBPjANBgkqhkiG9w0BAQUFADBAMQswCQYDVQQGEwJVUzEaMBgGA1UEChMRVGVz\n" +
                "dCBDZXJ0aWZpY2F0ZXMxFTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw0wMTA0MTkxNDU3MjBaFw0xMTA0\n" +
                "MTkxNDU3MjBaMEoxCzAJBgNVBAYTAlVTMRowGAYDVQQKExFUZXN0IENlcnRpZmljYXRlczEfMB0GA1UE\n" +
                "AxMWbmFtZUNvbnN0cmFpbnRzIEROMSBDQTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAnL2vzTK+\n" +
                "WcGR2rmlezdUTUQkfIvzcTWRIVW2x+BxQPrPfoLqmpYZar4sY8ND0l3pQWcIFsGYAYmm2vHULqUxZMW9\n" +
                "R/dM3wqstOXd2JJVxvw/v4ajYB5lPNcrv8LyxxjVU2daqlYXBCfL9/O6417oYys1UKNtEp6n6HV/ZbEJ\n" +
                "G70CAwEAAaOB2DCB1TAfBgNVHSMEGDAWgBT7bNQtgZ7KJ3qeDbA86pq8h/9J6jAdBgNVHQ4EFgQUTi6j\n" +
                "59ndi6eCO0FKw558WSNXTlMwDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAP\n" +
                "BgNVHRMBAf8EBTADAQH/MFkGA1UdHgEB/wRPME2gSzBJpEcwRTELMAkGA1UEBhMCVVMxGjAYBgNVBAoT\n" +
                "EVRlc3QgQ2VydGlmaWNhdGVzMRowGAYDVQQLExFwZXJtaXR0ZWRTdWJ0cmVlMTANBgkqhkiG9w0BAQUF\n" +
                "AAOBgQC9ypqhZWCmrISRla+Nxp/vshOsUQcyF9Se7PBrkAfl37dg70aSgX0/6Xef8i5v3MRCar6lM8x+\n" +
                "coBMHK41VUG9g6VW2DAoCG3ajBCj48vN0Gd4dUwvsGAmmVuIwH0R/+2IBMp00341fpjIjUrMpxcxDFwe\n" +
                "Ve3YFugTb2fMnETR7A==");
        NameConstraints nameConstraints = CertificateExtensionsUtils.getNameConstraints(certificate);
        assertNotNull(nameConstraints);
        assertTrue(Utils.isCollectionNotEmpty(nameConstraints.getPermittedSubtrees()));
        assertFalse(Utils.isCollectionNotEmpty(nameConstraints.getExcludedSubtrees()));

        CertificateExtensions certificateExtensions = CertificateExtensionsUtils.getCertificateExtensions(certificate);
        NameConstraints nameConstraintsExt = certificateExtensions.getNameConstraints();
        assertNotNull(nameConstraintsExt);
        assertEquals(nameConstraints.getPermittedSubtrees().size(), nameConstraintsExt.getPermittedSubtrees().size());
        assertEquals(nameConstraints.getExcludedSubtrees().size(), nameConstraintsExt.getExcludedSubtrees().size());

        GeneralSubtree subtree = nameConstraintsExt.getPermittedSubtrees().get(0);
        assertEquals(GeneralNameType.DIRECTORY_NAME, subtree.getGeneralNameType());
        assertEquals("OU=permittedSubtree1,O=Test Certificates,C=US", subtree.getValue());
    }

    @Test
    void getNameConstraintsExcludedSubtrees() {
        CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(
                "MIIFpzCCA4+gAwIBAgIId8arl05fKxEwDQYJKoZIhvcNAQELBQAwSDELMAkGA1UEBhMCRVMxEjAQBgNV\n" +
                        "BAcTCUJhcmNlbG9uYTEMMAoGA1UEChMDVVBDMRcwFQYDVQQDDA40LjIuMS4xMF8xMl9DQTAeFw0yMzA0\n" +
                        "MDEyMTQ2MDBaFw0zMzAzMzAyMzA1MDBaMEoxCzAJBgNVBAYTAkVTMRIwEAYDVQQHEwlCYXJjZWxvbmEx\n" +
                        "DDAKBgNVBAoTA1VQQzEZMBcGA1UEAwwQNC4yLjEuMTBfMTJfQ0ExMTCCAiIwDQYJKoZIhvcNAQEBBQAD\n" +
                        "ggIPADCCAgoCggIBAOARmqOjGDupM+huE0ouSRCKYzTcoOR37i7XKAxzj6wBnPS9UQdeZT9Kr+Ds+mFL\n" +
                        "SCHxDIRU8nZRDP2QKJKjJ+b9ccaPulQbT81R1lrWZjD2V+4px0SIJRE2BxlDmt9IObo2+YNrH1UMzyxO\n" +
                        "M/UViG6LNCIKpgQfY5jCSnnUqhT0bq97H3wFFCnyUuvmkA/dpBHHitMESv0JcBaSU8t0wDZCYus2L1bT\n" +
                        "/1AZg4yosH82tC/xbED+zAitj2K1YSkgD67Uq4x/p13EGioJR2reVxkD71XU6VDUprhyBZoml8BQxUSE\n" +
                        "pBMfOMiHsxrTPpxyf2kzegCfZRkVqEbNV4AaDLyO1bG/VWntb3dlTQQCccS+nYjeAfedo44jap/v6gpD\n" +
                        "xIJ6nn3lvKhazXd+gLzw1T8PzgQS8Jyziwo9R8wwANxElba7o3YV6svpaRDNest0fhjDEO3+qs/PSogG\n" +
                        "d77gFhGiSAKiW1HWA+LxB/zHS5BfmYpiB/Z05e3SzYTLRKJrKj3Aaj577oRwWlKRSrBNuZYmjLZ7b3yB\n" +
                        "Uemc4FmI/38ZnvBH7jUSpC92WSJqPrwFdMPtWMiTYU6foeniHbAHncxqqKQnSfautEwJdCqt/PZGs6JU\n" +
                        "zHFNGVWmvdpJ86Ryr6G4/tzJsVIGl5tbo3d/A6bEPl4501huJSOq6CxuzSo3AgMBAAGjgZIwgY8wDwYD\n" +
                        "VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUTo5IYuq9ZDFeRix5XVs30YnYd4kwCwYDVR0PBAQDAgEGMB0G\n" +
                        "A1UdHgEB/wQTMBGhDzANhgt3d3cudXBjLmVkdTARBglghkgBhvhCAQEEBAMCAAcwHgYJYIZIAYb4QgEN\n" +
                        "BBEWD3hjYSBjZXJ0aWZpY2F0ZTANBgkqhkiG9w0BAQsFAAOCAgEAAm8O/awSiMqf2LhhaZTPdaGZAvIP\n" +
                        "CkgaGRy1Q2pza0fvQSBSLZQrtZ+uPm8L0+EdOxitxvn1XxZcGR91YAtAkuO/WOOyk2OUAPpeeVwkKM7l\n" +
                        "TPY8yidn/frdbouObbogTGUBYPm8ffaYJP1oL4CNWedprgUeoal6UojJUAVksZxIUTFsq8CYi6duxOaZ\n" +
                        "SghufyECPbjF6rJyYT5pgz2bxMhmAwcyYbFIRubtvFQnzpO24i6uj3eBfm4N3jiIQ6SunLB2bFUfEZ6R\n" +
                        "DzARARa2MEhT6Z0wOmXRHSFotiSjD5RHUO3gfiog3GRb17GVaOPFaGIVFDWLoz4lpn2Rau162JtPOJaY\n" +
                        "0g9shTgtcjPvpxnX9QuMlRs+8GUCk/7A+Jav+OvODD+K1RVZADp9+ibxfJc8hXLUf+Wztr7dntVJ7Rqu\n" +
                        "wrmeXnGojSDj43sHuw6WwZttavf6gDqOSwvwVUAHcByWyzC9EdWZmjtRGKjA1xiBV5FcDEpExW6JVEME\n" +
                        "DgM7dZVkBZsofutnqNuw8s43Hh8dYZfO726HDjWEslx5tpj0Eez9nIooDQJKLfU6su8qQr2jBtVanLiD\n" +
                        "6YjSrzMisSCHBST5PfO2Vc+sWCnAsCHwh04TPUsdEUJA6uxQysdt3xvL9rGLYAiAJkHOwCxRCasc9pSv\n" +
                        "CTmr0rqyYtyxkfw===");
        NameConstraints nameConstraints = CertificateExtensionsUtils.getNameConstraints(certificate);
        assertNotNull(nameConstraints);
        assertFalse(Utils.isCollectionNotEmpty(nameConstraints.getPermittedSubtrees()));
        assertTrue(Utils.isCollectionNotEmpty(nameConstraints.getExcludedSubtrees()));

        CertificateExtensions certificateExtensions = CertificateExtensionsUtils.getCertificateExtensions(certificate);
        NameConstraints nameConstraintsExt = certificateExtensions.getNameConstraints();
        assertNotNull(nameConstraintsExt);
        assertEquals(nameConstraints.getPermittedSubtrees().size(), nameConstraintsExt.getPermittedSubtrees().size());
        assertEquals(nameConstraints.getExcludedSubtrees().size(), nameConstraintsExt.getExcludedSubtrees().size());

        GeneralSubtree subtree = nameConstraintsExt.getExcludedSubtrees().get(0);
        assertEquals(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER, subtree.getGeneralNameType());
        assertEquals("www.upc.edu", subtree.getValue());
    }

    @Test
    void getNameConstraintsPermittedSubtreeRFC822() {
        CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(
                "MIICqzCCAhSgAwIBAgIBQzANBgkqhkiG9w0BAQUFADBAMQswCQYDVQQGEwJVUzEaMBgGA1UEChMRVGVz\n" +
                        "dCBDZXJ0aWZpY2F0ZXMxFTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw0wMTA0MTkxNDU3MjBaFw0xMTA0\n" +
                        "MTkxNDU3MjBaME4xCzAJBgNVBAYTAlVTMRowGAYDVQQKExFUZXN0IENlcnRpZmljYXRlczEjMCEGA1UE\n" +
                        "AxMabmFtZUNvbnN0cmFpbnRzIFJGQzgyMiBDQTEwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOYG\n" +
                        "d2HszTJIsVTazKriCUJ/ExxUo4U4HEZN9+/XVXsQVkZYIzWtyCTC3IFmSAyb9ZEDGu3jmF/evXpfNXmx\n" +
                        "iURUu6W0bLEpIkZiVpPpTKqoJx2EHj+wXOfe31AD0OmKidXP66+LVgIJLWGMr3Msbzb4T3gpKb2ynQc2\n" +
                        "/XnE3RkbAgMBAAGjgaYwgaMwHwYDVR0jBBgwFoAU+2zULYGeyid6ng2wPOqavIf/SeowHQYDVR0OBBYE\n" +
                        "FON/hXqOojue7rgSHXkTqsS9LlmtMA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIB\n" +
                        "MAEwDwYDVR0TAQH/BAUwAwEB/zAnBgNVHR4BAf8EHTAboBkwF4EVLnRlc3RjZXJ0aWZpY2F0ZXMuZ292\n" +
                        "MA0GCSqGSIb3DQEBBQUAA4GBAJjXEGmrQ1/Muud+NZwajR9xit/32SNVvHI+/O7bopout/RnhJudrmsd\n" +
                        "qGlcSk0KXfcXI22cJOkAYe1M39znxgbaVitYYLxfsS+3O2pLpMgQMFCZuOJATfAQUlui+dVtPTaIam7j\n" +
                        "imms5Qam2K2SuZ/teJ2J/rIDHCOrIGktQS8H");
        NameConstraints nameConstraints = CertificateExtensionsUtils.getNameConstraints(certificate);
        assertNotNull(nameConstraints);
        assertTrue(Utils.isCollectionNotEmpty(nameConstraints.getPermittedSubtrees()));
        assertFalse(Utils.isCollectionNotEmpty(nameConstraints.getExcludedSubtrees()));

        CertificateExtensions certificateExtensions = CertificateExtensionsUtils.getCertificateExtensions(certificate);
        NameConstraints nameConstraintsExt = certificateExtensions.getNameConstraints();
        assertNotNull(nameConstraintsExt);
        assertEquals(nameConstraints.getPermittedSubtrees().size(), nameConstraintsExt.getPermittedSubtrees().size());
        assertEquals(nameConstraints.getExcludedSubtrees().size(), nameConstraintsExt.getExcludedSubtrees().size());

        GeneralSubtree subtree = nameConstraintsExt.getPermittedSubtrees().get(0);
        assertEquals(GeneralNameType.RFC822_NAME, subtree.getGeneralNameType());
        assertEquals(".testcertificates.gov", subtree.getValue());
    }

    @Test
    void getNameConstraintsPermittedSubtreeDNS() {
        CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(
                "MIICpzCCAhCgAwIBAgIBRjANBgkqhkiG9w0BAQUFADBAMQswCQYDVQQGEwJVUzEaMBgGA1UEChMRVGVz\n" +
                        "dCBDZXJ0aWZpY2F0ZXMxFTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw0wMTA0MTkxNDU3MjBaFw0xMTA0\n" +
                        "MTkxNDU3MjBaMEsxCzAJBgNVBAYTAlVTMRowGAYDVQQKExFUZXN0IENlcnRpZmljYXRlczEgMB4GA1UE\n" +
                        "AxMXbmFtZUNvbnN0cmFpbnRzIEROUzEgQ0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKF4cGWB\n" +
                        "eAaOHCGkAPlmkE9/9XtvEpanIGNf1g0ab0PBnZR8ffY+IK2+rwOeMVtfXmJbaxi/Z70teNn94XkPXH6P\n" +
                        "mz/pL170Q96CasAsPU2uQC4AtNjkUSeFbSoY7Ul2NaBYqLrWyQ7O3jEXdX76KQWqYcihAq1Jw+AEruMq\n" +
                        "98WrAgMBAAGjgaUwgaIwHwYDVR0jBBgwFoAU+2zULYGeyid6ng2wPOqavIf/SeowHQYDVR0OBBYEFHXn\n" +
                        "Z0cYCavxiIjbno3VF1KO/HN4MA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEw\n" +
                        "DwYDVR0TAQH/BAUwAwEB/zAmBgNVHR4BAf8EHDAaoBgwFoIUdGVzdGNlcnRpZmljYXRlcy5nb3YwDQYJ\n" +
                        "KoZIhvcNAQEFBQADgYEAzUV5anoiOD8wQQnetIFcg5wLnNlrdPixWje4q2JQcPnqZk3TW9O0GDtWHmZw\n" +
                        "VoS3PixQlJPHZGvkliTKM9vO7a8J2FDl/ZFRNrm2rHFjZxygk+UTwj+SI4CO8kmtSesvV0ViWwNNyfOV\n" +
                        "/nmvBjqy6pEbTnCDpax2/2P2ruVALCk===");
        NameConstraints nameConstraints = CertificateExtensionsUtils.getNameConstraints(certificate);
        assertNotNull(nameConstraints);
        assertTrue(Utils.isCollectionNotEmpty(nameConstraints.getPermittedSubtrees()));
        assertFalse(Utils.isCollectionNotEmpty(nameConstraints.getExcludedSubtrees()));

        CertificateExtensions certificateExtensions = CertificateExtensionsUtils.getCertificateExtensions(certificate);
        NameConstraints nameConstraintsExt = certificateExtensions.getNameConstraints();
        assertNotNull(nameConstraintsExt);
        assertEquals(nameConstraints.getPermittedSubtrees().size(), nameConstraintsExt.getPermittedSubtrees().size());
        assertEquals(nameConstraints.getExcludedSubtrees().size(), nameConstraintsExt.getExcludedSubtrees().size());

        GeneralSubtree subtree = nameConstraintsExt.getPermittedSubtrees().get(0);
        assertEquals(GeneralNameType.DNS_NAME, subtree.getGeneralNameType());
        assertEquals("testcertificates.gov", subtree.getValue());
    }

    @Test
    void getNameConstraintsExcludeedSubtreeIPAddresses() {
        CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(
                "MIIFojCCA4qgAwIBAgIJAOMWrsjU/s6/MA0GCSqGSIb3DQEBCwUAMD0xCzAJBgNVBAYTAkdCMQ8wDQYDVQQHDAZMb25kb24xEDAOBgNVBAoMB0RlbW8gQ0ExCzAJBgNVBAsMAklUMB4XDTE3MDUwNDE1NDQyM1oXDTM3MDQyOTE1NDQyM1owPTELMAkGA1UEBhMCR0IxDzANBgNVBAcMBkxvbmRvbjEQMA4GA1UECgwHRGVtbyBDQTELMAkGA1UECwwCSVQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCy6709MthSnIg6jl9+fgSdqdok56ElUVVaWiF0skZy17skS05zkdLXT15Su4Ffqs7kRawO4IHZvNVcoVGOkz4xnG4UT8w9dhtu10yUBbs/hi4/KWtdUFNvu2xU0vEzxuLjCZNyOmy5+rYBTfD6RIZ3eaElE5dZv0syZfG3WoVJMCYZt3KL7O0FtXSd6lCqUNE+bcbxEZ6Av4aJNMGMKK+3ML1lDwmyDalUnkOlcTkxlUt2mBt4MUHzc3fmjY4GgfjlyjKp1bzrBVU5sGrGGiZgH/kYvqABsUyaf3ejvg413YB66bAOr1sMvm1HGnqock8NpEYCJmWGDBox2s6o/nNO1i1+eE11Iyty24wx1Wwx1VMXd08CYDPpdhkkfN9LK+8yK7CpOViOy6/aXc2h7W0QHvWXCHGoEPDjGPKhSVzB2YR/+Nxlei9SjiI1cOE0ThTH1ikO3/3+S3yTKGZUJT8Mlra7IUBGfbwm63WRyEI9rlowhtGnA7bNtRPekiA95TqYmf5ZGYyksCsownYMU8Onm0JkDu5smeV+UGuqV5kXRiCOKoxdbGiJXWYZHNXEc1rnnDzN5TMJK3S2qLh0IpAJtQwhS++Oi0oTD3bjsyF9RPtDFnxYbxQJYGO/ig5WG1MQ97QMcUu94ll6vcjm8B14OUEkSzOVvxJtsaeldquRWQIDAQABo4GkMIGhMB0GA1UdDgQWBBQBMXxWPYExW1n/j0gJPuO7idEwQDAfBgNVHSMEGDAWgBQBMXxWPYExW1n/j0gJPuO7idEwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjA+BgNVHR4BAf8ENDAyoTAwCocIAAAAAAAAAAAwIocgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwDQYJKoZIhvcNAQELBQADggIBAAxNFDaTK70DtoX5NkWpfiNau1yyFGryygqbcTQAwkm8U+qp3Ktwf59eQfCd6fwq0aZXHbF+oLTuJrF9SWrx7RG5maZjAHXQKC52x5c6jYoWxhBiWcBGf9nYMTs16PKi0gRr5MLWaGsDWG8hMxZPeDW7S7c8Z1UXEul36AyHKMON56lqB7i2/b1VB18eDW8g6Y7fyWvNhJBJx5tgAq+zgQNBaKfmmwP3XoRG2WZXN28+vX6rgpSG9oCei26A4/BYEp37tC2VMTaJ8rvAWaRr+B3jYes94a25E/q1Vp1/IZBY8nCMZgsz5tusROI+rQPdZPV8AJVSgQsfPZFmBY9V9vMYkuiuTTtnzNCovrVU5sQWau+oOKYz/nsip0A7Bq1ZKhcSs3Bzpn1sh870yLWL1ALOLQf2SGrK/lRK+jcPSifqcme7kUQqjX2+gSn9j0deM3UMoEEfVNt39jnzmDVlxyFzhszLCZFzE+X4sKuKSsrSCVZdzqC3SKgWrJLTEJajoI5I3pFf4hM9kuinlijOQXtQjPERWeBiUhEHBqFeLZOvDMcru4UPmaDe5G3J5vNDzk3jvNwc/w1hvESgb8/aiNZFYqNN0bL1RXAH7LknjK/MZvCZ+nBvjWQMfLhbn6TZqiRHSo55e3DCiCCtffEdGjiPOUdjWRPd97YEp0Oon62s");
        NameConstraints nameConstraints = CertificateExtensionsUtils.getNameConstraints(certificate);
        assertNotNull(nameConstraints);
        assertFalse(Utils.isCollectionNotEmpty(nameConstraints.getPermittedSubtrees()));
        assertTrue(Utils.isCollectionNotEmpty(nameConstraints.getExcludedSubtrees()));

        CertificateExtensions certificateExtensions = CertificateExtensionsUtils.getCertificateExtensions(certificate);
        NameConstraints nameConstraintsExt = certificateExtensions.getNameConstraints();
        assertNotNull(nameConstraintsExt);
        assertEquals(nameConstraints.getPermittedSubtrees().size(), nameConstraintsExt.getPermittedSubtrees().size());
        assertEquals(nameConstraints.getExcludedSubtrees().size(), nameConstraintsExt.getExcludedSubtrees().size());

        assertEquals(2, nameConstraintsExt.getExcludedSubtrees().size());
        GeneralSubtree subtree = nameConstraintsExt.getExcludedSubtrees().get(0);
        assertEquals(GeneralNameType.IP_ADDRESS, subtree.getGeneralNameType());
        assertEquals("#0000000000000000", subtree.getValue());

        subtree = nameConstraintsExt.getExcludedSubtrees().get(1);
        assertEquals(GeneralNameType.IP_ADDRESS, subtree.getGeneralNameType());
        assertEquals("#0000000000000000000000000000000000000000000000000000000000000000", subtree.getValue());
    }

    @Test
    void noRevAvailTest() {
        CertificateToken certificateToken = DSSUtils.loadCertificateFromBase64EncodedString("MIIDbzCCAlegAwIBAgIBZTANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjMwNzI5MDcyNDU0WhcNMjUwNzI5MDcyNDU0WjBAMRYwFAYDVQQDDA1uZXctZ29vZC11c2VyMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIjMQH4OOGw5YcjEWlxpJbVnXrilX6dqwQntzybiW2VZw7evxvvDDPQ3w1YPB1Ombmldc/CU3iwp4IXJRVcmKqqXN66nYnm+ZNXbKS6bHWSCip/UItwFWEito2zji2EtlERqa3zu8uzgJK5ysrMr+vkidaCm5u0G+FpLTPIB1/9xirRED/qk1wT5DGIxMpHmS5r/5AfBOCZK81uqCQ0wnJnb4UMSlwyWcxTmOdAn1Y15mf5xqgoSWZRxDueVWbiCo3aFhelUR63EZ5R6YDIOEpurfWnJpfPlso3wqMNiUe4iEKNsuwRckfRPTC+qvxMd+VeYUFgQ3z4NYOIXtoyyYMCAwEAAaNnMGUwOQYIKwYBBQUHAQEELTArMCkGCCsGAQUFBzABhh1odHRwOi8vZHNzLm5vd2luYS5sdS9wa2kvb2NzcDAJBgNVHTgEAgUAMB0GA1UdDgQWBBSF+j+sm6FZa0TqltNRq6JcM9tutDANBgkqhkiG9w0BAQsFAAOCAQEArSXynLOuSpuk3GiYw6Jcsd7YhIGff4lNnjsB+HhmpEUAAmg2uTJ2Bq9z2hR128gdy8ji0Fo3c8UTDTyw4nzQO/NY85gcoAp2jc/9ZVZg89BujlBE+SkRI4FNKgyjp8VT3XLkaNYgCZB+yaiWoJyDPTyOKfv8ornkEzzfc5MTK15KbqHPTZJ8v5XbdnmevOs3iCgT81XLsjhhydtdJhikP8cB4hsGD41yrUy8L3J9Lzn9tegXhecnLLZv4lrEPEVMiVkzUYPiMXVhvKLguBLWPKoKGnA3D9BPcDueG3B+Bim5D+x+VN85jwYKwkrbvJnzHE+02ry/eetn0DOIjGKkzg==");
        NoRevAvail noRevAvail = CertificateExtensionsUtils.getNoRevAvail(certificateToken);
        assertNotNull(noRevAvail);
        assertFalse(noRevAvail.isCritical());
        assertTrue(noRevAvail.isNoRevAvail());

        CertificateExtensions certificateExtensions = CertificateExtensionsUtils.getCertificateExtensions(certificateToken);
        NoRevAvail noRevAvailExt = certificateExtensions.getNoRevAvail();
        assertNotNull(noRevAvailExt);
        assertFalse(noRevAvailExt.isCritical());
        assertTrue(noRevAvailExt.isNoRevAvail());
    }

}
