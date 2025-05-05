package eu.europa.esig.dss.xades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESLevelBWithTwoParallelEmbeddedEvidenceRecordOneInvalidTest extends AbstractXAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/X-E-ERS-two-parallel-ers-one-invalid.xml");
    }

    @Override
    protected CertificateVerifier getOfflineCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getOfflineCertificateVerifier();
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
        certificateVerifier.setTrustedCertSources(trustedCertificateSource);
        return certificateVerifier;
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        super.checkEvidenceRecords(diagnosticData);

        assertEquals(2, diagnosticData.getEvidenceRecords().size());
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        byte[] digestValue = null;
        int validErCounter = 0;
        int invalidErCounter = 0;
        for (EvidenceRecordWrapper evidenceRecordWrapper : diagnosticData.getEvidenceRecords()) {
            List<XmlDigestMatcher> digestMatchers = evidenceRecordWrapper.getDigestMatchers();
            assertEquals(1, digestMatchers.size());

            XmlDigestMatcher xmlDigestMatcher = digestMatchers.get(0);
            assertEquals(DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE, xmlDigestMatcher.getType());
            assertTrue(xmlDigestMatcher.isDataFound());
            assertEquals(DigestAlgorithm.SHA256, xmlDigestMatcher.getDigestMethod());
            assertNotNull(xmlDigestMatcher.getDigestValue());

            if (xmlDigestMatcher.isDataIntact()) {
                ++validErCounter;
            } else {
                ++invalidErCounter;
            }

            if (digestValue == null) {
                digestValue = xmlDigestMatcher.getDigestValue();
            } else {
                assertFalse(Arrays.equals(digestValue, xmlDigestMatcher.getDigestValue()));
            }
        }
        assertNotNull(digestValue);
        assertEquals(1, validErCounter);
        assertEquals(1, invalidErCounter);
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        int validErCounter = 0;
        int invalidErCounter = 0;
        for (EvidenceRecordWrapper evidenceRecordWrapper : diagnosticData.getEvidenceRecords()) {
            if (Utils.isCollectionNotEmpty(evidenceRecordWrapper.getEvidenceRecordScopes())) {
                int sigScopeCounter = 0;
                int fileScopeCounter = 0;
                for (XmlSignatureScope signatureScope : evidenceRecordWrapper.getEvidenceRecordScopes()) {
                    if (SignatureScopeType.SIGNATURE == signatureScope.getScope()) {
                        assertEquals(evidenceRecordWrapper.getParent().getId(), signatureScope.getName());
                        ++sigScopeCounter;
                    } else if (SignatureScopeType.FULL == signatureScope.getScope()) {
                        assertNotNull(signatureScope.getName());
                        ++fileScopeCounter;
                    }
                }
                assertEquals(1, sigScopeCounter);
                assertEquals(1, fileScopeCounter);

                ++validErCounter;
            } else {
                ++invalidErCounter;
            }
        }
        assertEquals(1, validErCounter);
        assertEquals(1, invalidErCounter);
    }

    @Override
    protected void checkEvidenceRecordCoverage(DiagnosticData diagnosticData, SignatureWrapper signature) {
        int validErCounter = 0;
        int invalidErCounter = 0;
        int validTstCounter = 0;
        int invalidTstCounter = 0;
        for (EvidenceRecordWrapper evidenceRecordWrapper : diagnosticData.getEvidenceRecords()) {
            List<XmlSignatureScope> evidenceRecordScopes = evidenceRecordWrapper.getEvidenceRecordScopes();

            boolean sigScopeFound = false;
            boolean docScopeFound = false;
            for (XmlSignatureScope signatureScope : evidenceRecordScopes) {
                if (SignatureScopeType.SIGNATURE == signatureScope.getScope()) {
                    assertEquals(evidenceRecordWrapper.getParent().getId(), signatureScope.getName());
                    assertNotNull(signatureScope.getDescription());
                    assertTrue(signatureScope.getDescription().contains(evidenceRecordWrapper.getParent().getId()));
                    sigScopeFound = true;
                } else if (SignatureScopeType.FULL == signatureScope.getScope()) {
                    assertNotNull(signatureScope.getName());
                    assertNotNull(signatureScope.getDescription());
                    assertTrue(Utils.isCollectionNotEmpty(signatureScope.getTransformations()));
                    docScopeFound = true;
                }
            }

            if (Utils.collectionSize(evidenceRecordScopes) == 0) {
                assertFalse(sigScopeFound);
                assertFalse(docScopeFound);
                ++invalidErCounter;
            } else if (Utils.collectionSize(evidenceRecordScopes) == 2) {
                assertTrue(sigScopeFound);
                assertTrue(docScopeFound);
                ++validErCounter;
            }

            List<TimestampWrapper> timestampList = evidenceRecordWrapper.getTimestampList();
            assertEquals(1, timestampList.size());
            TimestampWrapper timestampWrapper = timestampList.get(0);

            List<XmlSignatureScope> timestampScopes = timestampWrapper.getTimestampScopes();

            sigScopeFound = false;
            docScopeFound = false;
            for (XmlSignatureScope signatureScope : timestampScopes) {
                if (SignatureScopeType.SIGNATURE == signatureScope.getScope()) {
                    assertEquals(evidenceRecordWrapper.getParent().getId(), signatureScope.getName());
                    assertNotNull(signatureScope.getDescription());
                    assertTrue(signatureScope.getDescription().contains(evidenceRecordWrapper.getParent().getId()));
                    sigScopeFound = true;
                } else if (SignatureScopeType.FULL == signatureScope.getScope()) {
                    assertNotNull(signatureScope.getName());
                    assertNotNull(signatureScope.getDescription());
                    assertTrue(Utils.isCollectionNotEmpty(signatureScope.getTransformations()));
                    docScopeFound = true;
                }
            }

            if (Utils.collectionSize(timestampScopes) == 0) {
                assertFalse(sigScopeFound);
                assertFalse(docScopeFound);
                ++invalidTstCounter;
            } else if (Utils.collectionSize(timestampScopes) == 2) {
                assertTrue(sigScopeFound);
                assertTrue(docScopeFound);
                ++validTstCounter;
            }
        }
        assertEquals(1, validErCounter);
        assertEquals(1, invalidErCounter);
        assertEquals(1, validTstCounter);
        assertEquals(1, invalidTstCounter);
    }

    @Override
    protected void checkEvidenceRecordType(EvidenceRecordWrapper evidenceRecord) {
        super.checkEvidenceRecordType(evidenceRecord);

        assertEquals(EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD, evidenceRecord.getEvidenceRecordType());
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XAdES_BASELINE_B, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 2;
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        List<SignatureWrapper> signatures = diagnosticData.getSignatures();

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);
        List<XmlTimestampedObject> coveredObjects = evidenceRecord.getCoveredObjects();
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects));

        assertEquals(Utils.collectionSize(signatures), coveredObjects.stream()
                .filter(r -> TimestampedObjectType.SIGNATURE == r.getCategory()).count());
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects.stream()
                .filter(r -> TimestampedObjectType.SIGNED_DATA == r.getCategory()).collect(Collectors.toList())));

        assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredCertificates()));
        assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredRevocations()));
        assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredTimestamps()));
        assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignedData()));
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        boolean validERFound = false;
        boolean invalidERFound = false;
        for (EvidenceRecordWrapper evidenceRecordWrapper : diagnosticData.getEvidenceRecords()) {
            for (TimestampWrapper timestampWrapper : evidenceRecordWrapper.getTimestampList()) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());

                if (Utils.isCollectionNotEmpty(timestampWrapper.getTimestampScopes())) {
                    validERFound = true;
                } else {
                    invalidERFound = true;
                }
            }
        }
        assertTrue(validERFound);
        assertTrue(invalidERFound);
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        int sigWithErCounter = 0;
        for (String sigId : simpleReport.getSignatureIdList()) {
            int validERCounter = 0;
            int invalidERCounter = 0;
            List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(sigId);
            if (Utils.isCollectionNotEmpty(signatureEvidenceRecords)) {
                assertEquals(2, signatureEvidenceRecords.size());

                for (XmlEvidenceRecord evidenceRecord : signatureEvidenceRecords) {
                    if (Indication.FAILED == simpleReport.getIndication(evidenceRecord.getId())) {
                        assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(evidenceRecord.getId()));
                        ++invalidERCounter;
                    } else {
                        ++validERCounter;
                    }
                }

                ++sigWithErCounter;
            }
            assertEquals(1, validERCounter);
            assertEquals(1, invalidERCounter);
        }
        assertEquals(1, sigWithErCounter);
    }

}
