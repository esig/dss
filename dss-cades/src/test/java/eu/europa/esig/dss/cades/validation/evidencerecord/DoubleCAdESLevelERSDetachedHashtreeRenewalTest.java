package eu.europa.esig.dss.cades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class DoubleCAdESLevelERSDetachedHashtreeRenewalTest extends AbstractCAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(CAdESLevelBWithEmbeddedEvidenceRecordTest.class.getResourceAsStream("/validation/evidence-record/Double-C-E-ERS-detached_hashtree_renewal.p7m"));
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new InMemoryDocument("Hello World !!!".getBytes(), "test.text", MimeTypeEnum.TEXT));
    }

    @Override
    protected CertificateSource getTrustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIID9zCCAt+gAwIBAgICA+owDQYJKoZIhvcNAQENBQAwUDETMBEGA1UEAwwKZWUtcm9vdC1jYTEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMB4XDTI0MDUyOTE0MDc0MloXDTI2MDMyOTE0MDc0MlowUDETMBEGA1UEAwwKZWUtZ29vZC1jYTEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxZM/rbAWvJHZjrp/qr5Av1MwOLhFvel4zxHjMMohkC5hd+NtRbjySZyu8cdP45XdS0v3iuKJLICTWgn9KjF1b2ZkJtLFcI8N+FGmhXV3LHYXUv2EwgHWAZjkUhGIEPhnyR00N1z04skeOB4FVsT4TFggpfLtr5UqU/UPCpibOMwJDtVRs4xwD4H8cLexA0kfxVLGdFb/7HMFWr40wBDJpDm3U/D89Vdplk0Geuq3y8TwvsLxei7TxOe5a1Atu6kigTSSW3cliOCsvp9LqtyyEI6ArQSqU7qEzBRNp5r17ON7MCR3k6skteYTgc94m7uBOTKvjeZ7qJkGfzS+YYW7TQIDAQABo4HaMIHXMA4GA1UdDwEB/wQEAwIBBjBEBgNVHR8EPTA7MDmgN6A1hjNodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcmwvZWUtcm9vdC1jYS5jcmwwTwYIKwYBBQUHAQEEQzBBMD8GCCsGAQUFBzAChjNodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvZWUtcm9vdC1jYS5jcnQwHQYDVR0OBBYEFHTh0YBIYhJdtMrcrCihyQgXpRfCMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggEBADGP79hvKGNsveCb/OLdRVpDUltUNjAHR5QjXohPZ3INuEgaPIU4gNJ1jfzNIruSmjFvapu7aYk2gJcixcRV0PSL0n9Bs0qOKy6HivKLT+aaT21f97Pajxm8bp2/gdcMCu5HJlOiIv62S/8nEVV2X0ipqJRIVVG4YaK60BSp5Xz0Vx2ffkfEO+uGFADGN8rgt/fog5rlrQekt95KC5eFaxU5CBVb5e9EqCEOw3iuD7LBJDE6EZs0xgoSHTmhnMU3dDayiK4mM4WtjfoPK3sgKv+6HzLdbRqlu///guXYQHyVgl9x+/VrNjq4JSl3X9Ogigz7fC8VGKVyQWrBudkQmek="));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIDVzCCAj+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjQwNDI5MTQwNzM3WhcNMjYwNDI5MTQwNzM3WjBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDpJ5KdGo5TcfX6X2eHaPUAu6+joZ6dSZH6RK0nMBWbw+gYQnWWQQ6ryN3jLINTYTD2ArQlBj7PVA8F2GjV4WzOH5rBc/nfG6f8jpEr1hRW1x/ebZQs0QoVr7goGT5RD+Wy3rE9PdzEI96JuvkPW9IUrlUkr392GPS6/XcJ8PiFNcac7/hTGoWhAPKx3GAn2upxfEtb8fpcQvPeshp3kFyZjNzHBK406PSDhEv2v8Cf2vRLvJev5UYLNWLHeFudxSiyf10Hs67rCgawAwFY3S7gnMid+9VdrlzQ3CQ+g9z7Nc1julh3mr9nHK6psWjfnEnqVeCmxqc3e2tlYMr/CTU5AgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUO5fzoz60aYHnoF5UJ3UVdaGZLyQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAvcAIIf5Bv1F3vzk0DGW7fQezwMfA+6V4uyfM4gHN2lszUkIKHVLTszwHoyyfjdtvsLENV1b2v651BvX0sxTEW+FZ+tTsbh0CtqV+ELB0L0P9Z9HOwankoLVvZJ/cyE8XuapHLRWF0dPSl613uubysJeDxv7DO0wC5DQ4oVTbBTAmDaZdyTuqnwLqDLA7hrg0soXhwlx97tZ8knHjPNO7FCYMOow+bLS/PP2nQUYM42kon3uHJeucocetkb5GRNe8wz7Qsuw1n+FAtCIVPpQavbN5OzqOKrD1abDoOwxsbbyhKJBZhB2oM6CU1T9hBGCAnnExpXx+03B7Qd4VhRzmeQ=="));
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
            assertEquals(EvidenceRecordIncorporationType.EXTERNAL_EVIDENCE_RECORD, evidenceRecordWrapper.getIncorporationType());
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
        assertEquals(3, timestampList.size());

        int firstTstCounter = 0;
        int tstRenewalCounter = 0;
        int arcTstChainRenewalCounter = 0;
        for (TimestampWrapper timestampWrapper : timestampList) {
            assertNotNull(timestampWrapper.getProductionTime());
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureIntact());
            assertTrue(timestampWrapper.isSignatureValid());

            assertTrue(timestampWrapper.isSigningCertificateIdentified());
            assertTrue(timestampWrapper.isSigningCertificateReferencePresent());
            assertFalse(timestampWrapper.isSigningCertificateReferenceUnique());

            boolean messageImprintFound = false;
            boolean masterSigDMFound = false;
            boolean tstRenewalDMFound = false;
            boolean arcObjDMFound = false;
            for (XmlDigestMatcher xmlDigestMatcher : timestampWrapper.getDigestMatchers()) {
                assertTrue(xmlDigestMatcher.isDataFound());
                assertTrue(xmlDigestMatcher.isDataIntact());

                if (DigestMatcherType.MESSAGE_IMPRINT == xmlDigestMatcher.getType()) {
                    messageImprintFound = true;
                } else if (DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE == xmlDigestMatcher.getType()) {
                    masterSigDMFound = true;
                } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP == xmlDigestMatcher.getType()) {
                    tstRenewalDMFound = true;
                } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == xmlDigestMatcher.getType()) {
                    arcObjDMFound = true;
                } else {
                    fail(String.format("Not expected type : '%s'", xmlDigestMatcher.getType()));
                }
            }
            assertTrue(messageImprintFound);

            if (masterSigDMFound && arcObjDMFound) {
                ++arcTstChainRenewalCounter;
            } else if (tstRenewalDMFound) {
                ++tstRenewalCounter;
            } else {
                ++firstTstCounter;
            }
        }
        assertEquals(1, firstTstCounter);
        assertEquals(1, tstRenewalCounter);
        assertEquals(1, arcTstChainRenewalCounter);
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
        assertEquals(8, evidenceRecord.getCoveredCertificates().size());
        assertEquals(3, evidenceRecord.getCoveredRevocations().size());
        assertEquals(0, evidenceRecord.getCoveredEvidenceRecords().size());

        List<TimestampWrapper> timestampList = evidenceRecord.getTimestampList();
        TimestampWrapper timestampWrapper = timestampList.get(0);

        assertEquals(3, timestampWrapper.getTimestampedSignedData().size());
        assertEquals(2, timestampWrapper.getTimestampedSignatures().size());
        assertEquals(2, timestampWrapper.getTimestampedTimestamps().size());
        assertEquals(8, timestampWrapper.getTimestampedCertificates().size());
        assertEquals(3, timestampWrapper.getTimestampedRevocations().size());
        assertEquals(1, timestampWrapper.getTimestampedEvidenceRecords().size());
    }

    @Override
    protected void verifyCertificateSourceData(SignatureCertificateSource certificateSource, FoundCertificatesProxy foundCertificates) {
        // skip because a sig-tst has multiple signing-cert refs
    }

}
