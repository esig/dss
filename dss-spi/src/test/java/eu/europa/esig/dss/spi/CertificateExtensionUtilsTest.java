package eu.europa.esig.dss.spi;

import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.extension.AuthorityInformationAccess;
import eu.europa.esig.dss.model.x509.extension.AuthorityKeyIdentifier;
import eu.europa.esig.dss.model.x509.extension.CRLDistributionPoints;
import eu.europa.esig.dss.model.x509.extension.CertificateExtensions;
import eu.europa.esig.dss.model.x509.extension.CertificatePolicies;
import eu.europa.esig.dss.model.x509.extension.CertificatePolicy;
import eu.europa.esig.dss.model.x509.extension.ExtendedKeyUsages;
import eu.europa.esig.dss.model.x509.extension.InhibitAnyPolicy;
import eu.europa.esig.dss.model.x509.extension.NameConstraints;
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

public class CertificateExtensionUtilsTest {

    private static CertificateToken certificateWithAIA;

    private static CertificateToken certificateOCSP;

    @BeforeAll
    public static void init() {
        certificateWithAIA = DSSUtils.loadCertificate(new File("src/test/resources/TSP_Certificate_2014.crt"));
        assertNotNull(certificateWithAIA);

        certificateOCSP = DSSUtils.loadCertificateFromBase64EncodedString(
                "MIIEXjCCAkagAwIBAgILBAAAAAABWLd6HkYwDQYJKoZIhvcNAQELBQAwMzELMAkGA1UEBhMCQkUxEzARBgNVBAMTCkNpdGl6ZW4gQ0ExDzANBgNVBAUTBjIwMTYzMTAeFw0xNjEyMTAxMTAwMDBaFw0xODAxMjkxMTAwMDBaMC4xHzAdBgNVBAMTFkJlbGdpdW0gT0NTUCBSZXNwb25kZXIxCzAJBgNVBAYTAkJFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzD0B0c4gBx/wumeE2l/Wcz5FoMSUIuRNIySH2pJ3yfKR/u/FWCOzcrJvDMdmgzR33zGb4/fZel9YlI6xcN08Yd7GkP0/WtbHUhGUPERV76Vvyrk2K/EH/IG2gtxYB+7pkA/ZZycdyjc4IxHzBOiGofP9lDkPD05GSqI7MjVf6sNkZSnHcQSKwkaCGhAshJMjHzShEsSzOgX9kXceBFPTt6Hd2prVmnMTyAwURbQ6gFHbgfxB8JLMya95U6391nGQC66ScH1GhIwd9KSn+yBY0cazJ3nIrc8wd0yGYBgPK78jN3MvAsb1ydfs7kE+Wf95z9oRMiw62Glxh/ksLS/tTQIDAQABo3gwdjAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFBgKRBywCTroyvAErr7p657558Y9MBMGA1UdJQQMMAoGCCsGAQUFBwMJMB8GA1UdIwQYMBaAFM6Al2fQrdlOxJlqgCcikM0RNRCHMA8GCSsGAQUFBzABBQQCBQAwDQYJKoZIhvcNAQELBQADggIBAFuZrqcwt23UiiJdRst66MEBRyKbgPsQM81Uq4FVrAnV8z3l8DDUv+A29KzCPO0GnHSatqA7DNhhMzoBRC42PqCpuvrj8VEWHd43AuPOLaikE04a5tVh6DgW8b00s6Yyf/PuDHCsg2C2MqY71MUR9GcnI7ngR2SyWQGpbsf/wfjujNxEB0+SOwMDTgIAikaueHGZbYkwvlRpL6wm2ENvrE8OvKt7NlNsaWJ4KtQo0QS5Ku+Y2BDA3bX+g8eNLQkaXTycgL4X3MyE5pBOl1OW3KOjJdfyLF+Sii+JKjNf8ZQWk0xvkBEI+nhCzDXhtKAcrkTKlXE25MiUnYoRsXkXgrzYftxAMxvFOXJji/hnX5Fe/3SBAHaE+jU6yC5nk6Q9ERii8mL0nHouMlZWSiAuXtlZDFrzwtLD2ITBECe4X60BDQfb/caO2u3HcWoG1AOvGxfQB0cMmP2njCdDf8UOqryiyky4t7Jj3ghOvETjWlwMw5ObhZ8yj8p6qFAt7+EVJfpUc1gDAolS/hJoLzohbL5LnCAnUAWsFpvG3qW1ky+X0MePXi6q/boqj2tcC4IDdsYS6RHPBvzl5+yLDccrGx1s/7vQYTMNyX0dYZzuxFZxx0bttWfjqLz3hFHlAEVmLCyUkSz761CbaT9u/G4tPP4Q8ApFfSskPI57lbLWIcwP");
        assertNotNull(certificateOCSP);
    }

    @Test
    public void getCertificatePolicies() {
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
    public void getSKI() {
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
    public void getAuthorityKeyIdentifier() {
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
    public void getAccessLocation() {
        CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
        AuthorityInformationAccess aia = CertificateExtensionsUtils.getAuthorityInformationAccess(certificate);
        assertNotNull(aia);
        List<String> ocspAccessLocations = aia.getOcsp();
        assertEquals(1, Utils.collectionSize(ocspAccessLocations));
        assertEquals("http://ocsp.luxtrust.lu", ocspAccessLocations.get(0));
        assertEquals(ocspAccessLocations, CertificateExtensionsUtils.getOCSPAccessUrls(certificate));
    }

    @Test
    public void getCAAccessLocations() {
        CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
        AuthorityInformationAccess aia = CertificateExtensionsUtils.getAuthorityInformationAccess(certificate);
        assertNotNull(aia);
        List<String> caLocations = aia.getCaIssuers();
        assertEquals(1, Utils.collectionSize(caLocations));
        assertEquals("http://ca.luxtrust.lu/LTQCA.crt", caLocations.get(0));
        assertEquals(caLocations, CertificateExtensionsUtils.getCAIssuersAccessUrls(certificate));
    }

    @Test
    public void getCrlUrls() {
        CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
        CRLDistributionPoints crlDistributionPoints = CertificateExtensionsUtils.getCRLDistributionPoints(certificate);
        assertNotNull(crlDistributionPoints);
        List<String> crlUrls = crlDistributionPoints.getCrlUrls();
        assertEquals(1, Utils.collectionSize(crlUrls));
        assertEquals("http://crl.luxtrust.lu/LTQCA.crl", crlUrls.get(0));
        assertEquals(crlUrls, CertificateExtensionsUtils.getCRLAccessUrls(certificate));
    }

    @Test
    public void isOCSPSigning() {
        ExtendedKeyUsages extendedKeyUsage = CertificateExtensionsUtils.getExtendedKeyUsage(certificateOCSP);
        assertNotNull(extendedKeyUsage);
        assertTrue(extendedKeyUsage.getOids().contains(ExtendedKeyUsage.OCSP_SIGNING.getOid()));

        extendedKeyUsage = CertificateExtensionsUtils.getExtendedKeyUsage(certificateWithAIA);
        assertNotNull(extendedKeyUsage);
        assertFalse(extendedKeyUsage.getOids().contains(ExtendedKeyUsage.OCSP_SIGNING.getOid()));
    }

    @Test
    public void hasIdPkixOcspNoCheckExtension() {
        assertTrue(CertificateExtensionsUtils.hasOcspNoCheckExtension(certificateOCSP));
        assertFalse(CertificateExtensionsUtils.hasOcspNoCheckExtension(certificateWithAIA));
    }

    @Test
    public void hasValAssuredShortTermCertsExtension() {
        CertificateToken shortTermCertificate = DSSUtils.loadCertificateFromBase64EncodedString("MIIDJjCCAg6gAwIBAgIIMMSTGSdLPxQwDQYJKoZIhvcNAQENBQAwKDEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczELMAkGA1UEBhMCTFUwHhcNMjEwNzAxMTAwMTI5WhcNMjEwNzAxMTAwNjI5WjA2MQwwCgYDVQQDDANBIGExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxCzAJBgNVBAYTAkxVMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsW0yfJBqh9CtbfOtsZcEAEvzzfPusdhZNv0JSq8frKGMqJwTgjnkMJd9D3sEHUBJP0ryAmK9L5S+lWOGDhdYcE8K00k3hZSHyrOdRblB0SZhtXIgeGD7ESdTU9xPCf4Ze7xSI08zlk9NmTaj5Xqfyako8sxHAQapdXw8kfG0Ol6UhfMg7MjN8/wZrIVUYZzBQP3RFKHFQIms+pxfWxvETsynn/n2rOjuAsV0aTWGUAeWJRFJxKLSTrHQiQULVS1MHIIkdbQZxMA+Jn3dXwVdJLX/JRSvEOBqGRrvGQtYN2vNdrJlNHP0WGcSAddweWs7Ar+Pp7Qm/HEQF5+EOPUQDQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCBsAwIwYIKwYBBQUHAQMEFzAVMBMGBgQAjkYBBjAJBgcEAI5GAQYBMA0GBwQAi+xJAgEEAgUAMA0GCSqGSIb3DQEBDQUAA4IBAQBAYj8mdKsj/mMoM4HXL/w+xeK0iM55eGyBNprwxECoCH8ZCgVrVTb3eKttTXYrXjk3Yqpg3amkm7aV94iXJ0qLER/2C9lHLv6h1CoxYCdevAUSVOIzF0SJj54dxrwDQ7uTFXRe2etOg+hmEhj3OBpd/5vMfdIViYHtpPoCyZoQyGLztUt1k8/JvBe91UGAEnWx0nvokehkTgueq7dsTjBit4dlCmfmIzQUUWCgNpe1S1nEb0B/BCXaqPRhYx1//2T/5gR1lKe36HHp5rUURKT8NsS76lfxdor9Ag3mVmsw1NcVtDiFo0molO84+B53yqRP2wCU7MtfKfCX9CocgVNF");
        assertTrue(CertificateExtensionsUtils.hasValAssuredShortTermCertsExtension(shortTermCertificate));
        assertFalse(CertificateExtensionsUtils.hasValAssuredShortTermCertsExtension(certificateOCSP));
    }

    @Test
    public void readOCSPAccessLocationsAndStopOnceLoopDetected() {
        CertificateToken caTokenA = DSSUtils.loadCertificateFromBase64EncodedString("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");
        CertificateToken caTokenB = DSSUtils.loadCertificateFromBase64EncodedString("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");
        assertTrue(caTokenA.isSignedBy(caTokenB));
        assertTrue(caTokenB.isSignedBy(caTokenA));
        AuthorityInformationAccess aia = CertificateExtensionsUtils.getAuthorityInformationAccess(caTokenA);
        assertNotNull(aia);
        List<String> ocspAccessLocations = aia.getOcsp();
        assertNotNull(ocspAccessLocations);
        assertEquals(ocspAccessLocations, CertificateExtensionsUtils.getOCSPAccessUrls(caTokenA));
    }

    @Test
    public void getSubjectAlternativeNames() {
        CertificateToken cert = DSSUtils.loadCertificateFromBase64EncodedString(
                "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");
        assertNotNull(cert);

        SubjectAlternativeNames subjectAlternativeNamesExtension = CertificateExtensionsUtils.getSubjectAlternativeNames(cert);
        assertNotNull(subjectAlternativeNamesExtension);
        List<String> subjectAlternativeNames = subjectAlternativeNamesExtension.getNames();
        assertNotNull(subjectAlternativeNames);
        assertEquals(1, Utils.collectionSize(subjectAlternativeNames));

        CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
        subjectAlternativeNamesExtension = CertificateExtensionsUtils.getSubjectAlternativeNames(certificate);
        assertNotNull(subjectAlternativeNamesExtension);
        subjectAlternativeNames = subjectAlternativeNamesExtension.getNames();
        assertNotNull(subjectAlternativeNames);
        assertEquals(0, Utils.collectionSize(subjectAlternativeNames));
    }

    @Test
    public void getPolicyConstraints() {
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
    public void getPolicyConstraintsTwo() {
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
    public void getInhibitAnyPolicy() {
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
    public void getNameConstraintsPermittedSubtrees() {
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
        assertTrue(Utils.isCollectionNotEmpty(nameConstraints.getPermittedSubtrees()));
        assertFalse(Utils.isCollectionNotEmpty(nameConstraints.getExcludedSubtrees()));

        CertificateExtensions certificateExtensions = CertificateExtensionsUtils.getCertificateExtensions(certificate);
        NameConstraints nameConstraintsExt = certificateExtensions.getNameConstraints();
        assertNotNull(nameConstraintsExt);
        assertEquals(nameConstraints.getPermittedSubtrees().size(), nameConstraintsExt.getPermittedSubtrees().size());
        assertEquals(nameConstraints.getExcludedSubtrees().size(), nameConstraintsExt.getExcludedSubtrees().size());
    }

}
