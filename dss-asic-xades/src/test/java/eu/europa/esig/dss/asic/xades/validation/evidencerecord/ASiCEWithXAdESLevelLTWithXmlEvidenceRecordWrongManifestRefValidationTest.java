package eu.europa.esig.dss.asic.xades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEWithXAdESLevelLTWithXmlEvidenceRecordWrongManifestRefValidationTest extends AbstractASiCEWithXAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/xades-lt-with-er-multi-data-wrong-manifest-reference.sce");
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 4;
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertEquals(1, Utils.collectionSize(detachedEvidenceRecords));
        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);

        int validRefsCounter = 0;
        int invalidRefsCounter = 0;
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        assertEquals(getNumberOfExpectedEvidenceScopes(), Utils.collectionSize(referenceValidationList));
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            assertTrue(referenceValidation.isFound());
            if (referenceValidation.isIntact()) {
                ++validRefsCounter;
            } else {
                ++invalidRefsCounter;
            }
        }
        assertEquals(3, validRefsCounter);
        assertEquals(1, invalidRefsCounter);

        List<TimestampedReference> timestampedReferences = evidenceRecord.getTimestampedReferences();
        assertTrue(Utils.isCollectionNotEmpty(timestampedReferences));

        int tstCounter = 0;

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        for (TimestampToken timestampToken : timestamps) {
            assertTrue(timestampToken.isProcessed());
            assertTrue(timestampToken.isMessageImprintDataFound());
            assertTrue(timestampToken.isMessageImprintDataIntact());

            if (tstCounter > 0) {
                List<ReferenceValidation> tstReferenceValidationList = timestampToken.getReferenceValidations();
                assertTrue(Utils.isCollectionNotEmpty(tstReferenceValidationList));

                boolean archiveTstDigestFound = false;
                boolean archiveTstSequenceDigestFound = false;
                for (ReferenceValidation referenceValidation : tstReferenceValidationList) {
                    if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP.equals(referenceValidation.getType())) {
                        archiveTstDigestFound = true;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE.equals(referenceValidation.getType())) {
                        archiveTstSequenceDigestFound = true;
                    }
                    assertTrue(referenceValidation.isFound());
                    assertTrue(referenceValidation.isIntact());
                }

                if (tstReferenceValidationList.size() == 1) {
                    assertTrue(archiveTstDigestFound);
                } else {
                    assertTrue(archiveTstSequenceDigestFound);
                }

            }

            ++tstCounter;
        }
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecord = diagnosticData.getEvidenceRecords().get(0);

        int validRefsCounter = 0;
        int invalidRefsCounter = 0;
        List<XmlDigestMatcher> digestMatcherList = evidenceRecord.getDigestMatchers();
        assertEquals(getNumberOfExpectedEvidenceScopes(), Utils.collectionSize(digestMatcherList));
        for (XmlDigestMatcher digestMatcher : digestMatcherList) {
            assertNotNull(digestMatcher.getName());
            assertTrue(digestMatcher.isDataFound());
            if (digestMatcher.isDataIntact()) {
                ++validRefsCounter;
            } else {
                ++invalidRefsCounter;
            }
        }
        assertEquals(3, validRefsCounter);
        assertEquals(1, invalidRefsCounter);
    }

    @Override
    protected void verifyCertificateSourceData(SignatureCertificateSource certificateSource, FoundCertificatesProxy foundCertificates) {
        // skip (time-stamp contains multiple sign-cert refs)
    }

    @Override
    protected void checkTimestamp(DiagnosticData diagnosticData, TimestampWrapper timestampWrapper) {
        assertNotNull(timestampWrapper.getProductionTime());
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertTrue(timestampWrapper.isSignatureValid());

        List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            assertTrue(xmlDigestMatcher.isDataFound());
            assertTrue(xmlDigestMatcher.isDataIntact());
        }
        if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
            assertNotNull(timestampWrapper.getArchiveTimestampType());
        }

        assertTrue(timestampWrapper.isSigningCertificateIdentified());
        assertTrue(timestampWrapper.isSigningCertificateReferencePresent());

        if (timestampWrapper.isTSAGeneralNamePresent()) {
            assertTrue(timestampWrapper.isTSAGeneralNameMatch());
            assertTrue(timestampWrapper.isTSAGeneralNameOrderMatch());
        }

        CertificateRefWrapper signingCertificateReference = timestampWrapper.getSigningCertificateReference();
        assertNotNull(signingCertificateReference);
        assertTrue(signingCertificateReference.isDigestValuePresent());
        assertTrue(signingCertificateReference.isDigestValueMatch());
        if (signingCertificateReference.isIssuerSerialPresent()) {
            assertTrue(signingCertificateReference.isIssuerSerialMatch());
        }

        CertificateWrapper signingCertificate = timestampWrapper.getSigningCertificate();
        assertNotNull(signingCertificate);
        String signingCertificateId = signingCertificate.getId();
        String certificateDN = diagnosticData.getCertificateDN(signingCertificateId);
        String certificateSerialNumber = diagnosticData.getCertificateSerialNumber(signingCertificateId);
        assertEquals(signingCertificate.getCertificateDN(), certificateDN);
        assertEquals(signingCertificate.getSerialNumber(), certificateSerialNumber);

        assertTrue(Utils.isCollectionEmpty(timestampWrapper.foundCertificates()
                .getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE)));

        assertTrue(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampedObjects()));

        if (timestampWrapper.getType().isContentTimestamp() || timestampWrapper.getType().isArchivalTimestamp() ||
                timestampWrapper.getType().isDocumentTimestamp() || timestampWrapper.getType().isContainerTimestamp()) {
            assertTrue(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampScopes()));
        } else if (timestampWrapper.getType().isEvidenceRecordTimestamp()) {
            assertTrue(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampScopes()));
        } else {
            assertFalse(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampScopes()));
        }
    }

    protected void verifySimpleReport(SimpleReport simpleReport) {
        for (String sigId : simpleReport.getSignatureIdList()) {
            List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(sigId);
            assertTrue(Utils.isCollectionNotEmpty(signatureEvidenceRecords));
            assertEquals(1, Utils.collectionSize(signatureEvidenceRecords));

            XmlEvidenceRecord xmlEvidenceRecord = signatureEvidenceRecords.get(0);
            assertNotNull(xmlEvidenceRecord.getPOETime());
            assertEquals(Indication.FAILED, xmlEvidenceRecord.getIndication());
            assertEquals(SubIndication.HASH_FAILURE, xmlEvidenceRecord.getSubIndication());

            List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> evidenceRecordScopes = xmlEvidenceRecord.getEvidenceRecordScope();
            assertEquals(getNumberOfExpectedEvidenceScopes(), Utils.collectionSize(evidenceRecordScopes));

            boolean sigNameFound = false;
            for (eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope evidenceRecordScope : evidenceRecordScopes) {
                assertEquals(SignatureScopeType.FULL, evidenceRecordScope.getScope());
                if (simpleReport.getTokenFilename(sigId).equals(evidenceRecordScope.getName())) {
                    sigNameFound = true;
                }
            }
            assertTrue(sigNameFound);

            XmlTimestamps timestamps = xmlEvidenceRecord.getTimestamps();
            assertNotNull(timestamps);
            assertEquals(1, Utils.collectionSize(timestamps.getTimestamp()));

            XmlTimestamp xmlTimestamp = timestamps.getTimestamp().get(0);
            assertEquals(Indication.PASSED, xmlTimestamp.getIndication());

            List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> timestampScopes = xmlTimestamp.getTimestampScope();
            assertEquals(getNumberOfExpectedEvidenceScopes(), Utils.collectionSize(timestampScopes));
        }
    }

}
