package eu.europa.esig.dss.asic.xades.validation.evidencerecord;

import eu.europa.esig.dss.asic.common.validation.AbstractASiCWithEvidenceRecordTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordOrigin;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCSWithXAdESLevelERSValidationTest extends AbstractASiCWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/asic-xades-ers.scs");
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(1, Utils.collectionSize(diagnosticData.getSignatures()));
    }

    @Override
    protected CertificateSource getTrustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIGfDCCBGSgAwIBAgILegm/vKLCvZC9lZ4wDQYJKoZIhvcNAQELBQAwgacxCzAJBgNVBAYTAkFUMQ0wCwYDVQQIEwRXaWVuMQ0wCwYDVQQHEwRXaWVuMSMwIQYDVQQKExplLWNvbW1lcmNlIG1vbml0b3JpbmcgR21iSDEqMCgGA1UECxMhR0xPQkFMVFJVU1QgQ2VydGlmaWNhdGlvbiBTZXJ2aWNlMSkwJwYDVQQDEyBHTE9CQUxUUlVTVCAyMDE1IEFEVkFOQ0VEIFNFQUwgMTAeFw0yNDA1MzExNDEwNThaFw0yOTA2MDMxNjEwNThaMHIxCzAJBgNVBAYTAkxUMRAwDgYDVQQHEwdWaWxuaXVzMRYwFAYDVQQKEw1CYWxUc3RhbXAgVUFCMRswGQYDVQRhExJWQVRMVC0xMDAwMTE2MzgxMTAxHDAaBgNVBAMTE0JhbFRzdGFtcCBRVFNBIFRTVTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMWrOQ7zZ8aQkCbSyIuAGDYK9/gAPAKtvlm41pl0Is9MwZwmuKbDyldtr3jVjcYmPOZWxrSl1kwtviLgCaWRSiZBtAb7Wx8apdjKgnrY6JXlmZV53HtKg2cQMLjOzJ0JdCovzaHRJ51zUvqpgragcZ3qLSDKfXZaIQX+3RHYXG5TYJKGffENripAu4FLBio63r+jEFvzyXrzy992p3SU+hay0k7/B3QP25wJESOi0JbBuDtYXYvd/gI0Tknowf4Hbg0UIaHFX6iOo02XV1M7suRDWL4tH36iqNA2CC6cZhdT3HqEycQWYtUXg6YNa2JLtvL/T+iWiZmjWQ8UeW8TtJAgMBAAGjggHbMIIB1zAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIGQDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAdBgNVHQ4EFgQUVmh7+SVt6nXpejBfYZ1xKkmSp6swHwYDVR0jBBgwFoAUjpHCtQYEHXOOh3vp/IntBffUqcMwgZMGCCsGAQUFBwEBBIGGMIGDMCYGCCsGAQUFBzABhhpodHRwOi8vb2NzcC5nbG9iYWx0cnVzdC5ldTBZBggrBgEFBQcwAoZNaHR0cDovL3NlcnZpY2UuZ2xvYmFsdHJ1c3QuZXUvc3RhdGljL2dsb2JhbHRydXN0LTIwMTUtYWR2YW5jZWQtc2VhbC0xLWRlci5jZXIwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL3NlcnZpY2UuZ2xvYmFsdHJ1c3QuZXUvc3RhdGljL2dsb2JhbHRydXN0LTIwMTUtYWR2YW5jZWQtc2VhbC0xLmNybDBWBgNVHSAETzBNMEsGCCooACQBAQgBMD8wPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cuZ2xvYmFsdHJ1c3QuZXUvY2VydGlmaWNhdGUtcG9saWN5Lmh0bWwwFQYIKwYBBQUHCwIECQYHBACL7EkBAjANBgkqhkiG9w0BAQsFAAOCAgEACbom4TZkdR2hlbLqHyuzKHvpcLPcJqhVAEZ68AqamuUV7al/AaMI9F8FTVfQ8zh6Y2LFC8RuFNn40fOmdryMKLO+12TTkRJjKOIXrg/8udySVH0zKY9hIedXe5KsBkfRQbBrG1Rr7kEVCraN2Kbkuc0eUuhYXFz5SJJz0tsDXTaY4HW3uZ2BohLHZtwHJr5zpA4aCrkXWzbxXSN0DUwioDT2+UeEPpiN4AKOV2KH9N6pByumzxjZjI3StCGcvo6Ib0WNeNEPNeeU5GrzqRotCERIGtdd5hZu1no7ExJLdthIkUs+0OR7qMMUk1mKmvsbY6x8O5x3UNebV/DCptsvMFWVDFxvGMZelFzyigYAyrAW3Y1O37n5Sw/nPu88xOmk++vyubRZLWQ0O+QVXG/guf5XH3kqM3yZhZLhDRSU1hNF/2uHFiSTzKaN1GLRY7VZGxbH6BEUI4J5/2zl2Q4zsI/5Sxi15BGfnjP3uXr19vD1sfSRTN6DstTWn0V49hofv6FkNM0qqgCl6YPkBefabUaeN5e2vu3zS3Njc5QjkMlS/AJQMedMEu6n1xdq92UurlwlwiUFn5vtgRhPAMaed4LwAhRMMNEEq1RxEOUSZTuRBpXx9iLJzdB7TeNZHpbxAF4Bdxhl816/SZIvFW9Vtqr35NQMtKiGSwk/KTgtmfg="));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIEVzCCAr+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjQwMzA2MTQxNzM4WhcNMjYwMzA2MTQxNzM4WjBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC+K0Z+J9AqSvFci0UuaI9BWe20I+48DaUEwLaMSTQ38r7VvJdkoc6ojeJizwJUgqMg46KRYkhyaXkUMBDwo5tYFP6uKXeQ7xJOixxNVl642Xxbvky8eOxmRJiixYIFWZcDkiIEOX46iyq3+4u+8FQGa63tgzUxY716a7aa7e48GoukUJ1pM/hUUV/rB/Tq6IPeG7U+C/WyMptpPWCIeRwxE44qelH/KZVm7c+IdrVj0klH2CO2fBhTE+yS84ri1NTaxIhRQCy4fnhtUYG6qD8W21NGtZuUjk9HVQoY69kRPntPye9wcLCwpgXpKGHtP5kdeCYkM3ewaD3ikevgB5b7xYUZ3D7z5UmLfaNjZSlnGDhp3mnjIpdkw6HDZlJLn6eo7+DI7xRr9rWsGDOiZIqzEHp4LR6zAzRX2Pa5xsWUDb6GL6SuJfr08F+k3OPid54CiI/M557X4/USLD2BVDoK3XmNPhJMaB6MYXyAdLBYMnzpDz1AWFoBH32NrTjjyI8CAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSNWhFLS3EpjxLi6S52RA5b9Gc/jjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4IBgQA8Gt2uotXF4HIwI+aHOuYI5C4FAMDKeHVnWTHh9eNpAB0R08Yke+oCpBdJJYYYzLr9WGIqlBH344ksUATVbvzy2W1bh4Uj6WkZ0jgMIbZAb2HqRwtXNhDy9q3QZA4UXh/0zvm6K2EOWAUMFdjJ1i380EcnbH1FNTOxErD3GJJ3YA7/ZU5ALPdWmgbnecsAa4WcFfHhTzfaXBdYTCLIgXlzQ2DB7COgA3Gtvybj1M0qo1FRSA71AQ+A5JidymcOPp6q2Jwn2gO9lw2Ng3g05PDkWxzUwVM6PaaiA8szyZAZ/ffO5d7dwvvSTOezQb4jnCb47eag/fKXHzK+rh3AJi3c7N6hOu0ntPJQgjKN0Ya1Gg9/18LcUPBuaxZHPjlrjM+ELfF4vcE+kankns/Mcwe3/m2fajWISMKEE6H+YqSjRHSiyrdagmXk8aUk1H3JOVcxs+YCYpMKKm8wvkFFmpO5L+rVl3PRP5OaU12gd2eZ83TqsTm9l+iXI9/3i/ioung="));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
        return trustedCertificateSource;
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        super.checkSignatureLevel(diagnosticData);

        assertEquals(SignatureLevel.XAdES_ERS, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertFalse(Utils.isCollectionNotEmpty(detachedEvidenceRecords));
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        super.checkEvidenceRecords(diagnosticData);

        assertEquals(1, Utils.collectionSize(diagnosticData.getEvidenceRecords()));
    }

    @Override
    protected void checkEvidenceRecordOrigin(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        assertEquals(EvidenceRecordOrigin.SIGNATURE, evidenceRecordWrapper.getOrigin());
        assertEquals(EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD, evidenceRecordWrapper.getEvidenceRecordType());
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordDigestMatchers(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        assertEquals(1, evidenceRecordWrapper.getDigestMatchers().size());

        XmlDigestMatcher digestMatcher = evidenceRecordWrapper.getDigestMatchers().get(0);
        assertEquals(DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE, digestMatcher.getType());
        assertNotNull(digestMatcher.getDigestMethod());
        assertNotNull(digestMatcher.getDigestValue());
        assertTrue(digestMatcher.isDataFound());
        assertTrue(digestMatcher.isDataIntact());
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);

        List<TimestampWrapper> timestampList = evidenceRecordWrapper.getTimestampList();
        assertEquals(1, timestampList.size());

        TimestampWrapper timestampWrapper = timestampList.get(0);
        assertEquals(TimestampType.EVIDENCE_RECORD_TIMESTAMP, timestampWrapper.getType());
        assertNotNull(timestampWrapper.getProductionTime());
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertTrue(timestampWrapper.isSignatureValid());

        assertTrue(timestampWrapper.isSigningCertificateIdentified());
        assertTrue(timestampWrapper.isSigningCertificateReferencePresent());
        assertTrue(timestampWrapper.isSigningCertificateReferenceUnique());

        List<XmlSignatureScope> timestampScopes = timestampWrapper.getTimestampScopes();
        assertEquals(4, timestampScopes.size());

        int masterSigCounter = 0;
        int packageCounter = 0;
        int archiveEntriesCounter = 0;
        for (XmlSignatureScope signatureScope : timestampScopes) {
            if (SignatureScopeType.SIGNATURE == signatureScope.getScope()) {
                ++masterSigCounter;
            } else if (SignatureScopeType.FULL == signatureScope.getScope()) {
                assertEquals("package.zip", signatureScope.getName());
                    ++packageCounter;
            } else if (SignatureScopeType.ARCHIVED == signatureScope.getScope()) {
                assertNotNull(signatureScope.getName());
                ++archiveEntriesCounter;
            }
        }
        assertEquals(1, masterSigCounter);
        assertEquals(1, packageCounter);
        assertEquals(2, archiveEntriesCounter);
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordScopes(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);

        List<XmlSignatureScope> evidenceRecordScopes = evidenceRecordWrapper.getEvidenceRecordScopes();
        assertEquals(4, evidenceRecordScopes.size());

        int masterSigCounter = 0;
        int packageCounter = 0;
        int archiveEntriesCounter = 0;
        for (XmlSignatureScope signatureScope : evidenceRecordScopes) {
            if (SignatureScopeType.SIGNATURE == signatureScope.getScope()) {
                ++masterSigCounter;
            } else if (SignatureScopeType.FULL == signatureScope.getScope()) {
                assertEquals("package.zip", signatureScope.getName());
                ++packageCounter;
            } else if (SignatureScopeType.ARCHIVED == signatureScope.getScope()) {
                assertNotNull(signatureScope.getName());
                ++archiveEntriesCounter;
            }
        }
        assertEquals(1, masterSigCounter);
        assertEquals(1, packageCounter);
        assertEquals(2, archiveEntriesCounter);
    }

}
