package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XmlEvidenceRecordNoHashTreeInvalidDigestValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-no-hashtree.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new DigestDocument(DigestAlgorithm.SHA256, "hNS7x84dr9TdyUMAOk+yQxbDcghyVH4n3WOYqrgrbYc="));
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertTrue(Utils.isCollectionNotEmpty(detachedEvidenceRecords));

        for (EvidenceRecord evidenceRecord : detachedEvidenceRecords) {
            List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
            for (ReferenceValidation referenceValidation : referenceValidationList) {
                assertTrue(referenceValidation.isFound());
                assertTrue(referenceValidation.isIntact());
            }

            List<TimestampedReference> timestampedReferences = evidenceRecord.getTimestampedReferences();
            assertTrue(Utils.isCollectionNotEmpty(timestampedReferences));

            int tstCounter = 0;

            List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
            for (TimestampToken timestampToken : timestamps) {
                assertTrue(timestampToken.isProcessed());
                assertTrue(timestampToken.isMessageImprintDataFound());
                assertFalse(timestampToken.isMessageImprintDataIntact());

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
    }

    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(1, Utils.collectionSize(evidenceRecords));

        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);
        List<XmlDigestMatcher> digestMatchers = evidenceRecord.getDigestMatchers();
        assertEquals(1, digestMatchers.size());
        XmlDigestMatcher digestMatcher = digestMatchers.get(0);
        assertEquals(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT, digestMatcher.getType());
        assertNotNull(digestMatcher.getDigestMethod());
        assertNotNull(digestMatcher.getDigestValue());
        assertTrue(digestMatcher.isDataFound());
        assertTrue(digestMatcher.isDataIntact());
    }

    protected void checkTimestamp(DiagnosticData diagnosticData, TimestampWrapper timestampWrapper) {
        assertNotNull(timestampWrapper.getProductionTime());
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertFalse(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertFalse(timestampWrapper.isSignatureValid());

        List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
        assertEquals(1, digestMatchers.size());

        XmlDigestMatcher xmlDigestMatcher = digestMatchers.get(0);
        assertEquals(DigestMatcherType.MESSAGE_IMPRINT, xmlDigestMatcher.getType());
        assertTrue(xmlDigestMatcher.isDataFound());
        assertFalse(xmlDigestMatcher.isDataIntact());

        assertTrue(timestampWrapper.isSigningCertificateIdentified());
        assertTrue(timestampWrapper.isSigningCertificateReferencePresent());
        assertTrue(timestampWrapper.isSigningCertificateReferenceUnique());

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

        assertTrue(timestampWrapper.getType().isEvidenceRecordTimestamp());
        assertFalse(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampScopes()));
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        assertEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstEvidenceRecordId()));
        assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEvidenceRecordId()));
    }

}
