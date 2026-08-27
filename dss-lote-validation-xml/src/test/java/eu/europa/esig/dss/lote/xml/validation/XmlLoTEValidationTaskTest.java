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
package eu.europa.esig.dss.lote.xml.validation;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.lote.validation.LoTEValidationResult;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.validation.job.validation.ValidationResult;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XmlLoTEValidationTaskTest {

    private static final DSSDocument PUBEAA_PROVIDERS;
    private static final CertificateToken PUBEAA_PROVIDERS_SIGNER;

    static {
        PUBEAA_PROVIDERS = new FileDocument("src/test/resources/lote-pubeaa.xml");
        PUBEAA_PROVIDERS_SIGNER = DSSUtils.loadCertificate(new File("src/test/resources/lote-signer.cer"));;
    }

    @Test
    void testValid() {
        List<CertificateToken> potentialSigners = Collections.singletonList(PUBEAA_PROVIDERS_SIGNER);
        XmlLoTEValidationTask task = new XmlLoTEValidationTask(PUBEAA_PROVIDERS, getCertificateSource(potentialSigners));
        LoTEValidationResult result = task.get();
        assertNotNull(result);
        assertEquals(Indication.TOTAL_PASSED, result.getIndication());
        assertNotNull(result.getSigningTime());
        assertNotNull(result.getSigningCertificate());
        assertEquals(PUBEAA_PROVIDERS_SIGNER, result.getSigningCertificate());
    }

    @Test
    void testStructureError() {
        DSSDocument loteDoc = new FileDocument("src/test/resources/lote-pubeaa-not-compliant.xml");
        // LoTE shall be signed with a trusted certificate directly
        CertificateToken potentialSigner = DSSUtils.loadCertificateFromBase64EncodedString("MIIFdjCCA96gAwIBAgICBFcwDQYJKoZIhvcNAQELBQAwWjESMBAGA1UEAwwJRUFBUSBDZXJ0MSQwIgYDVQQKDBtRRUFBIFRydXN0IFNlcnZpY2UgUHJvdmlkZXIxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJFVTAeFw0yNTAyMTAxMDA1MjhaFw0yNzAyMTAxMDA1MjhaMFsxEzARBgNVBAMMCkFsaWNlIENlcnQxJDAiBgNVBAoMG1FFQUEgVHJ1c3QgU2VydmljZSBQcm92aWRlcjERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkVVMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAwvlryjNGJQY1m4T0XXVCdDOOgUOOx01vb2F4S+4Kc7p+XYAK5rYzr2l386EwwBxT3kJg5WHIDWLFxJdPCF3v1WR0s/9zYLDKyu71mPjMEXOPcK3qVnAEYfzdAq7pve40T9XGe+A3h99BePhL/VLKM4bITuSAprWkOlxU4IIFXBhlrL5NhASnGrVx/EHmVqUym3/lCCS6Nb9OrVdFkfAD1k/KjmY4Oe6O8dTEmsxvdZJkW4MVziKWsuulqJVLgiydvrkfLeq/MF5U6r6N5N8zEUx3qUF/nmAETldDZUVY3PMstfn7GuiUnzTQMgpkbYIDMcJLmoChdMRiNKhMLbf8k2O7Q/R2crnbxnmtrLmoNXCJ4vRgTXSxdIkdoPRgpnT/l/brLmUP+67c7+s3Dg+aCOappxIvtwXyGaUKjoD5yjOvVGfUy5bWR/26gobJ0C4CG04UkxWhZDhoe5vzYQcMJfFV0VgoHIl3OFBEjkaD6muent191Zn3EfdW5esjPlDLAgMBAAGjggFDMIIBPzAOBgNVHQ8BAf8EBAMCBsAwNwYIKwYBBQUHAQMEKzApMAgGBgQAjkYBATAIBgYEAI5GAQQwEwYGBACORgEGMAkGBwQAjkYBBgEwRAYDVR0fBD0wOzA5oDegNYYzaHR0cDovL2xvY2FsaG9zdDo5OTk5L3BraS1mYWN0b3J5L2NybC9FQUFRIENlcnQuY3JsMIGOBggrBgEFBQcBAQSBgTB/MDwGCCsGAQUFBzABhjBodHRwOi8vbG9jYWxob3N0Ojk5OTkvcGtpLWZhY3Rvcnkvb2NzcC9FQUFRIENlcnQwPwYIKwYBBQUHMAKGM2h0dHA6Ly9sb2NhbGhvc3Q6OTk5OS9wa2ktZmFjdG9yeS9jcnQvRUFBUSBDZXJ0LmNydDAdBgNVHQ4EFgQUexbMei5Jf0Nckwe9jkJeBYSA86owDQYJKoZIhvcNAQELBQADggGBAKVJ3WRux33Bks7eWrA+Q/Av/DWh4n/U1Uiem7qebW4M/Jbjfpw4gLc788D9Q7ENYL/ae25a+JrDew7XqMTZiAGOqPCZ6mP7qvJn62ROEYgzO9oBgS3ArH8bg+LmuYMTb73VdJMIQB/8mcTceEAvvUz5NMwiYWagHJQ7wMrQmN3ZGdVQ7pQ3wU9MuBzRrij6IN6r7S3TBSAHaDqqKBaK9Mvjt5kIsDdGzp88hhrNaQbdeU1fvE0sNNZfMf1JlgdTotJooGBTzeIFVIaNKpwW4X6dpYfRygJQC+Bokwg9FTwUKwgBbTZcTOZQ9kzQsyw0vEC4l6JCh97sq6NneE55ALq2z9Z1u08unM9bviTIKDNPn0GbwIjGzCEiQpETHQQ/SJTr7+jnH2kibPxvwu4I7K5PBIEcnDhAIvQ5DHl99R9YkSvTYOZQfHlGIySoiNMGWfzsR9TF9qg/42eUpcyrsCaQxiNZ+IwYse4/ZWIwg6LHnigSuDGnbY5GNGx2SX1Gcw==");
        List<CertificateToken> potentialSigners = Collections.singletonList(potentialSigner);
        XmlLoTEValidationTask task = new XmlLoTEValidationTask(loteDoc, getCertificateSource(potentialSigners));
        LoTEValidationResult result = task.get();
        assertNotNull(result);
        assertEquals(Indication.TOTAL_PASSED, result.getIndication());
        assertNotNull(result.getSigningTime());
        assertNotNull(result.getSigningCertificate());
        assertEquals(potentialSigner, result.getSigningCertificate());
    }

    @Test
    void testCACert() {
        DSSDocument loteDoc = new FileDocument("src/test/resources/lote-pubeaa-not-compliant.xml");
        // LoTE shall be signed with a trusted certificate directly
        CertificateToken potentialSigner = DSSUtils.loadCertificateFromBase64EncodedString("MIIEcjCCAtqgAwIBAgICBFYwDQYJKoZIhvcNAQELBQAwWjESMBAGA1UEAwwJQ0FRQyBDZXJ0MSQwIgYDVQQKDBtRRUFBIFRydXN0IFNlcnZpY2UgUHJvdmlkZXIxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJFVTAeFw0yMzAyMTAxMDA1MjhaFw0yOTAyMTAxMDA1MjhaMFoxEjAQBgNVBAMMCUVBQVEgQ2VydDEkMCIGA1UECgwbUUVBQSBUcnVzdCBTZXJ2aWNlIFByb3ZpZGVyMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCRVUwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC3Cd5sYdapFdkW/9WCXsT12OLINDPera2UhGxrOzKy806/wwYTsBf5aAkVTdXHopC1F07hbV1Zq5wAVY901igslOxyF8MxJf0LWQd5WeHjrBVXfKDRcfWrnrpqhF4pqIj1sTbgOvvRz7J8EWe06+i8ZKmZsSef9EdyhrxBrvViBHnbykqSwmNM18tIcE4zgX7HFxlCN+Ylw0W6F/nxQsJySDY+mGwlCIVN87m0J4ODnwhVFokoeWVpGn60cPwMbh7NNiyTY0m7dm4YuGzRoGgfwFj9wR+N14pPSKl0RQ6yj5G3f1j4cGtRSQ6YjhdEWQcLio3JClaloQfWpLMQ3iOetZQ+Z4JHHkLkQlWMTSWeFy1uFbbbIwcbg8jYlYRsNF9x/mo8sgm3iUe4fFMQr89/wxAHztNo1vQ8A2r0TDGBwY6+lR7kLGONyGnnORADcPx7vfiXihjKcWRDJHvlcaIgAvZsN1uHnfgtWL9Jc69WxQIV7Hh/dciCpas99jwNot8CAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTHgmbCeFkobK9RTZkIqoOk21B5gTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBgQDJxR99ZbA8moMXcwnN0JrLGsw7ptPjpe5E6V69H7Jrq4pJz+iBYAWfgEbMtNLa/qJPolqgOvHcJfv4FWeGQrCAsf3et9NUAA6LmDDyGlhHFjYW8brFrhrYQGvXSyL7iQ+Kwid4iltqs7wvVcQYHYCv82RSf07tSVFojjHS+vakylBfeek6QwitM05JmKt6UpPOvD1uFXMkCjGAdu036BZYsmzCFWaubjJvlxa41UYeECFS6EW1ystWBmi2JoCkrBCRIcvrIQSzYzn6DaLyAsvo2G2/lQnWHekX7OEdipN6/YopD2m2kyDjtlLlce1mvu3K7df9TCfVzTx81Sx01CcD6zugE6fZYq6FGGxtwQkyfPf8GgJi2oMD9eJ4DlRdBW+abh+hE1DHiic/zIye9UIrTkVwo4Le76aYyBh95EfTsN7rGJw1UE3XExMKXDxwCMQo3G/vs5a53u+eqF5bOUO9p7645a4PeTpnregdB7KgggrWM6v9/WIDgMbT+vJk0J4=");
        List<CertificateToken> potentialSigners = Collections.singletonList(potentialSigner);
        XmlLoTEValidationTask task = new XmlLoTEValidationTask(loteDoc, getCertificateSource(potentialSigners));
        LoTEValidationResult result = task.get();
        assertNotNull(result);
        assertEquals(Indication.INDETERMINATE, result.getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, result.getSubIndication());
        assertNotNull(result.getSigningTime());
        assertNotNull(result.getSigningCertificate());
        assertNotEquals(potentialSigner, result.getSigningCertificate());
    }

    @Test
    void testWrongCert() {
        CertificateToken potentialSigner = DSSUtils.loadCertificateFromBase64EncodedString("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");
        List<CertificateToken> potentialSigners = Collections.singletonList(potentialSigner);
        XmlLoTEValidationTask task = new XmlLoTEValidationTask(PUBEAA_PROVIDERS, getCertificateSource(potentialSigners));
        LoTEValidationResult result = task.get();
        assertNotNull(result);
        assertEquals(Indication.INDETERMINATE, result.getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, result.getSubIndication());
        assertNotNull(result.getSigningTime());
        assertNotNull(result.getSigningCertificate());
        assertNotEquals(potentialSigner, result.getSigningCertificate());
    }

    @Test
    void testNoCert() {
        XmlLoTEValidationTask task = new XmlLoTEValidationTask(PUBEAA_PROVIDERS, getCertificateSource(Collections.emptyList()));
        ValidationResult result = task.get();
        assertNotNull(result);
        assertEquals(Indication.INDETERMINATE, result.getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, result.getSubIndication());
        assertNotNull(result.getSigningTime());
        assertNotNull(result.getSigningCertificate());
    }

    @Test
    void testInvalidSignature() {
        DSSDocument loteDoc = new FileDocument("src/test/resources/lote-pubeaa-broken-sig.xml");
        List<CertificateToken> potentialSigners = Collections.singletonList(PUBEAA_PROVIDERS_SIGNER);
        XmlLoTEValidationTask task = new XmlLoTEValidationTask(loteDoc, getCertificateSource(potentialSigners));
        LoTEValidationResult result = task.get();
        assertNotNull(result);
        assertEquals(Indication.TOTAL_FAILED, result.getIndication());
        assertEquals(SubIndication.HASH_FAILURE, result.getSubIndication());
        assertNotNull(result.getSigningTime());
        assertNotNull(result.getSigningCertificate());
        assertEquals(PUBEAA_PROVIDERS_SIGNER, result.getSigningCertificate());
    }

    @Test
    void testJson() {
        DSSDocument loteDoc = new FileDocument("src/test/resources/lote-pubeaa.json");
        List<CertificateToken> potentialSigners = Collections.singletonList(PUBEAA_PROVIDERS_SIGNER);
        XmlLoTEValidationTask task = new XmlLoTEValidationTask(loteDoc, getCertificateSource(potentialSigners));
        Exception exception = assertThrows(IllegalInputException.class, task::get);
        assertTrue(exception.getMessage().contains("An XML file is expected : Unable to parse content (XML expected)"));
    }

    @Test
    void testNullCertSource() {
        assertThrows(NullPointerException.class, () -> new XmlLoTEValidationTask(PUBEAA_PROVIDERS, null));
    }

    @Test
    void testNullDoc() {
        CommonCertificateSource ccs = new CommonCertificateSource();
        assertThrows(NullPointerException.class, () -> new XmlLoTEValidationTask(null, ccs));
    }

    private CertificateSource getCertificateSource(List<CertificateToken> potentialSigners) {
        CertificateSource cs = new CommonCertificateSource();
        for (CertificateToken certificateToken : potentialSigners) {
            cs.addCertificate(certificateToken);
        }
        return cs;
    }

}
