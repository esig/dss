package eu.europa.esig.dss.asic.xades.validation.evidencerecord;

import eu.europa.esig.dss.asic.common.validation.AbstractASiCWithEvidenceRecordTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
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

class ASiCEWithXAdESLevelERSValidationTest extends AbstractASiCWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/asic-xades-ers.sce");
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(1, Utils.collectionSize(diagnosticData.getSignatures()));
    }

    @Override
    protected CertificateSource getTrustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
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
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        List<SignatureWrapper> signatures = diagnosticData.getSignatures();
        SignatureWrapper signatureWrapper = signatures.get(0);
        List<TimestampWrapper> timestampList = signatureWrapper.getTimestampList();
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
        assertEquals(3, timestampScopes.size());

        int masterSigCounter = 0;
        int archiveEntriesCounter = 0;
        for (XmlSignatureScope signatureScope : timestampScopes) {
            if (SignatureScopeType.SIGNATURE == signatureScope.getScope()) {
                ++masterSigCounter;
            } else if (SignatureScopeType.FULL == signatureScope.getScope()) {
                assertNotNull(signatureScope.getName());
                ++archiveEntriesCounter;
            }
        }
        assertEquals(1, masterSigCounter);
        assertEquals(2, archiveEntriesCounter);
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordScopes(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);

        List<XmlSignatureScope> evidenceRecordScopes = evidenceRecordWrapper.getEvidenceRecordScopes();
        assertEquals(3, evidenceRecordScopes.size());

        int masterSigCounter = 0;
        int archiveEntriesCounter = 0;
        for (XmlSignatureScope signatureScope : evidenceRecordScopes) {
            if (SignatureScopeType.SIGNATURE == signatureScope.getScope()) {
                ++masterSigCounter;
            } else if (SignatureScopeType.FULL == signatureScope.getScope()) {
                assertNotNull(signatureScope.getName());
                ++archiveEntriesCounter;
            }
        }
        assertEquals(1, masterSigCounter);
        assertEquals(2, archiveEntriesCounter);
    }

}
