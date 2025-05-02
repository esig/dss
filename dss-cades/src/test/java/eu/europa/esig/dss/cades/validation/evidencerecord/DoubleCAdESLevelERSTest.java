package eu.europa.esig.dss.cades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DoubleCAdESLevelERSTest extends AbstractCAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(CAdESLevelBWithEmbeddedEvidenceRecordTest.class.getResourceAsStream("/validation/evidence-record/Double-C-E-ERS.p7m"));
    }

    @Override
    protected CertificateSource getTrustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIEVzCCAr+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjQwMzA2MTQxNzM4WhcNMjYwMzA2MTQxNzM4WjBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC+K0Z+J9AqSvFci0UuaI9BWe20I+48DaUEwLaMSTQ38r7VvJdkoc6ojeJizwJUgqMg46KRYkhyaXkUMBDwo5tYFP6uKXeQ7xJOixxNVl642Xxbvky8eOxmRJiixYIFWZcDkiIEOX46iyq3+4u+8FQGa63tgzUxY716a7aa7e48GoukUJ1pM/hUUV/rB/Tq6IPeG7U+C/WyMptpPWCIeRwxE44qelH/KZVm7c+IdrVj0klH2CO2fBhTE+yS84ri1NTaxIhRQCy4fnhtUYG6qD8W21NGtZuUjk9HVQoY69kRPntPye9wcLCwpgXpKGHtP5kdeCYkM3ewaD3ikevgB5b7xYUZ3D7z5UmLfaNjZSlnGDhp3mnjIpdkw6HDZlJLn6eo7+DI7xRr9rWsGDOiZIqzEHp4LR6zAzRX2Pa5xsWUDb6GL6SuJfr08F+k3OPid54CiI/M557X4/USLD2BVDoK3XmNPhJMaB6MYXyAdLBYMnzpDz1AWFoBH32NrTjjyI8CAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSNWhFLS3EpjxLi6S52RA5b9Gc/jjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4IBgQA8Gt2uotXF4HIwI+aHOuYI5C4FAMDKeHVnWTHh9eNpAB0R08Yke+oCpBdJJYYYzLr9WGIqlBH344ksUATVbvzy2W1bh4Uj6WkZ0jgMIbZAb2HqRwtXNhDy9q3QZA4UXh/0zvm6K2EOWAUMFdjJ1i380EcnbH1FNTOxErD3GJJ3YA7/ZU5ALPdWmgbnecsAa4WcFfHhTzfaXBdYTCLIgXlzQ2DB7COgA3Gtvybj1M0qo1FRSA71AQ+A5JidymcOPp6q2Jwn2gO9lw2Ng3g05PDkWxzUwVM6PaaiA8szyZAZ/ffO5d7dwvvSTOezQb4jnCb47eag/fKXHzK+rh3AJi3c7N6hOu0ntPJQgjKN0Ya1Gg9/18LcUPBuaxZHPjlrjM+ELfF4vcE+kankns/Mcwe3/m2fajWISMKEE6H+YqSjRHSiyrdagmXk8aUk1H3JOVcxs+YCYpMKKm8wvkFFmpO5L+rVl3PRP5OaU12gd2eZ83TqsTm9l+iXI9/3i/ioung="));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIEaDCCA++gAwIBAgIUYgKXRHlVRnKUhBH9VqQi8YkYwxEwCgYIKoZIzj0EAwMwgbsxCzAJBgNVBAYTAkJFMREwDwYDVQQHDAhCcnVzc2VsczEwMC4GA1UECgwnS2luZ2RvbSBvZiBCZWxnaXVtIC0gRmVkZXJhbCBHb3Zlcm5tZW50MT8wPQYDVQQLDDZRVFNQOiBGUFMgUG9saWN5IGFuZCBTdXBwb3J0IC0gQk9TQSAoTlRSQkUtMDY3MTUxNjY0NykxDzANBgNVBAUTBjIwMjEwMTEVMBMGA1UEAwwMVGltZXN0YW1wIENBMB4XDTIyMTIwOTEwNTYwMloXDTI4MTIwOTEwNTYwMVowgYkxCzAJBgNVBAYTAkJFMREwDwYDVQQHDAhCcnVzc2VsczEsMCoGA1UECgwjUVRTUDogRlBTIFBvbGljeSBhbmQgU3VwcG9ydCAtIEJPU0ExGTAXBgNVBGEMEE5UUkJFLTA2NzE1MTY2NDcxHjAcBgNVBAMMFVRpbWVzdGFtcCBVbml0IDIwMjMwMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLmXpDLz9zw5cho43EAFbjEtjUpXD+tFEihjq7XzBldbtHQHV1cW9Ra+hpLjUa5CvJN+VWF9dEMECf1VZmAS/8ajggH/MIIB+zAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFOBOG9N1TbWHTgK2+qlaY8w8qpiZMHsGCCsGAQUFBwEBBG8wbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5laWRwa2kuYmVsZ2l1bS5iZS90cy90c2NhMjAyMTAxLmNydDAvBggrBgEFBQcwAYYjaHR0cDovL29jc3AuZWlkcGtpLmJlbGdpdW0uYmUvZWlkLzAwVgYDVR0gBE8wTTBABgdgOA0GA4doMDUwMwYIKwYBBQUHAgEWJ2h0dHBzOi8vcmVwb3NpdG9yeS5laWRwa2kuYmVsZ2l1bS5iZS90czAJBgcEAIvsQAEBMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMG0GCCsGAQUFBwEDBGEwXzAIBgYEAI5GAQEwEwYGBACORgEGMAkGBwQAjkYBBgIwPgYGBACORgEFMDQwMhYsaHR0cHM6Ly9yZXBvc2l0b3J5LmVpZHBraS5iZWxnaXVtLmJlL3Bkcy10c3MTAmVuMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwuZWlkcGtpLmJlbGdpdW0uYmUvdHMvdHNjYTIwMjEwMS5jcmwwHQYDVR0OBBYEFJohWdg9YkmxbhVR1YZX+NeXq5aTMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAwNnADBkAjAYALeaQLcKx7V9KnoYN36xjYXLzhbji3hkQMKqGQydMQjUrBp/xtr9UJjpd+qGxaoCMExzxfcWMa7bKav44FhXI9Mf8L5JVEpvzCwugzzjOVquOtX1m+DqAG7CQqhMweUVDQ=="));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIDaDCCAu2gAwIBAgIUcYtX/2tpPlocI17Yh6PvUfQBDyYwCgYIKoZIzj0EAwMwgeAxCzAJBgNVBAYTAkJFMREwDwYDVQQHDAhCcnVzc2VsczEwMC4GA1UECgwnS2luZ2RvbSBvZiBCZWxnaXVtIC0gRmVkZXJhbCBHb3Zlcm5tZW50MTYwNAYDVQQLDC1GUFMgSG9tZSBBZmZhaXJzIC0gQklLLUdDSSAoTlRSQkUtMDM2MjQ3NTUzOCkxOTA3BgNVBAsMMEZQUyBQb2xpY3kgYW5kIFN1cHBvcnQgLSBCT1NBIChOVFJCRS0wNjcxNTE2NjQ3KTEZMBcGA1UEAwwQQmVsZ2l1bSBSb290IENBNjAeFw0yMDA2MDMxMDAxMzFaFw00MDA2MDMxMDAxMzFaMIHgMQswCQYDVQQGEwJCRTERMA8GA1UEBwwIQnJ1c3NlbHMxMDAuBgNVBAoMJ0tpbmdkb20gb2YgQmVsZ2l1bSAtIEZlZGVyYWwgR292ZXJubWVudDE2MDQGA1UECwwtRlBTIEhvbWUgQWZmYWlycyAtIEJJSy1HQ0kgKE5UUkJFLTAzNjI0NzU1MzgpMTkwNwYDVQQLDDBGUFMgUG9saWN5IGFuZCBTdXBwb3J0IC0gQk9TQSAoTlRSQkUtMDY3MTUxNjY0NykxGTAXBgNVBAMMEEJlbGdpdW0gUm9vdCBDQTYwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR532ARaLVsPSf5Pz9+b5ExaxpCe8iGGkDgkbUlGM0ulbr0YqbKva7EoOAY+YL5ZJs8S0KIsuQNc0f2vgI8xcyPQHgeCaLcw0OzvmfCHf/OMOIozEKgKaAK6pHvaBXP0tijZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQEwHwYDVR0jBBgwFoAULqCIsAsNYonsHT/Un8ySRI5IaUYwHQYDVR0OBBYEFC6giLALDWKJ7B0/1J/MkkSOSGlGMA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNpADBmAjEAt2e2vVG4/aMjIokbQQuCnvI8so8rZl/IbKupMCJitfFi7oVlHllYFDdYMDTKWLZgAjEAsa2wuz3Ew6/68XXtIT+51snqkl2KLlaVgKXYlpTh2zqQBIBdKO1nMO/rQRfuZ701"));
        return trustedCertificateSource;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        super.checkNumberOfSignatures(diagnosticData);

        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertEquals(SignatureLevel.CAdES_ERS, signatureWrapper.getSignatureFormat());
        }
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 3;
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        super.checkEvidenceRecords(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        List<SignatureWrapper> signatures = diagnosticData.getSignatures();
        assertEquals(2, signatures.size());

        for (SignatureWrapper signatureWrapper : signatures) {
            List<EvidenceRecordWrapper> signatureEvidenceRecords = signatureWrapper.getEvidenceRecords();
            assertEquals(1, signatureEvidenceRecords.size());

            EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
            assertEquals(EvidenceRecordIncorporationType.INTERNAL_EVIDENCE_RECORD, evidenceRecordWrapper.getIncorporationType());
        }
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            assertNotNull(timestampWrapper.getProductionTime());
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureIntact());
            assertTrue(timestampWrapper.isSignatureValid());
        }
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        List<TimestampWrapper> timestampList = evidenceRecordWrapper.getTimestampList();
        assertEquals(1, timestampList.size());

        TimestampWrapper timestampWrapper = timestampList.get(0);
        assertNotNull(timestampWrapper.getProductionTime());
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertTrue(timestampWrapper.isSignatureValid());

        assertTrue(timestampWrapper.isSigningCertificateIdentified());
        assertTrue(timestampWrapper.isSigningCertificateReferencePresent());
        assertFalse(timestampWrapper.isSigningCertificateReferenceUnique());
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);

        List<XmlSignatureScope> evidenceRecordScopes = evidenceRecordWrapper.getEvidenceRecordScopes();
        assertEquals(3, evidenceRecordScopes.size());

        int docCounter = 0;
        int masterSigCounter = 0;
        int otherSigCounter = 0;
        for (XmlSignatureScope signatureScope : evidenceRecordScopes) {
            if (SignatureScopeType.FULL == signatureScope.getScope()) {
                ++docCounter;
            } else if (SignatureScopeType.SIGNATURE == signatureScope.getScope()) {
                if (evidenceRecordWrapper.getParent().getId().equals(signatureScope.getName())) {
                    assertTrue(signatureScope.getDescription().contains("Master"));
                    ++masterSigCounter;
                } else {
                    assertFalse(signatureScope.getDescription().contains("Master"));
                    ++otherSigCounter;
                }
            }
        }
        assertEquals(1, docCounter);
        assertEquals(1, masterSigCounter);
        assertEquals(1, otherSigCounter);

        List<TimestampWrapper> timestampList = evidenceRecordWrapper.getTimestampList();
        TimestampWrapper timestampWrapper = timestampList.get(0);

        docCounter = 0;
        masterSigCounter = 0;
        otherSigCounter = 0;
        for (XmlSignatureScope signatureScope : timestampWrapper.getTimestampScopes()) {
            if (SignatureScopeType.FULL == signatureScope.getScope()) {
                ++docCounter;
            } else if (SignatureScopeType.SIGNATURE == signatureScope.getScope()) {
                if (evidenceRecordWrapper.getParent().getId().equals(signatureScope.getName())) {
                    assertTrue(signatureScope.getDescription().contains("Master"));
                    ++masterSigCounter;
                } else {
                    assertFalse(signatureScope.getDescription().contains("Master"));
                    ++otherSigCounter;
                }
            }
        }
        assertEquals(1, docCounter);
        assertEquals(1, masterSigCounter);
        assertEquals(1, otherSigCounter);
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordTimestampedReferences(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);

        assertEquals(3, evidenceRecord.getCoveredSignedData().size());
        assertEquals(2, evidenceRecord.getCoveredSignatures().size());
        assertEquals(2, evidenceRecord.getCoveredTimestamps().size());
        assertEquals(11, evidenceRecord.getCoveredCertificates().size());
        assertEquals(3, evidenceRecord.getCoveredRevocations().size());
        assertEquals(0, evidenceRecord.getCoveredEvidenceRecords().size());

        List<TimestampWrapper> timestampList = evidenceRecord.getTimestampList();
        TimestampWrapper timestampWrapper = timestampList.get(0);

        assertEquals(3, timestampWrapper.getTimestampedSignedData().size());
        assertEquals(2, timestampWrapper.getTimestampedSignatures().size());
        assertEquals(2, timestampWrapper.getTimestampedTimestamps().size());
        assertEquals(11, timestampWrapper.getTimestampedCertificates().size());
        assertEquals(3, timestampWrapper.getTimestampedRevocations().size());
        assertEquals(1, timestampWrapper.getTimestampedEvidenceRecords().size());
    }

    @Override
    protected void verifyCertificateSourceData(SignatureCertificateSource certificateSource, FoundCertificatesProxy foundCertificates) {
        // skip because a sig-tst has multiple signing-cert refs
    }

}
