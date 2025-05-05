package eu.europa.esig.dss.cades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class CAdESLevelERSRenewedHashtreeTest extends AbstractCAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(CAdESLevelBWithEmbeddedEvidenceRecordTest.class.getResourceAsStream("/validation/evidence-record/C-E-ERS_renewed_hashtree.p7m"));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CAdES_ERS, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 2;
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        super.checkEvidenceRecords(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        assertEquals(EvidenceRecordIncorporationType.INTERNAL_EVIDENCE_RECORD, evidenceRecordWrapper.getIncorporationType());
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
            for (XmlDigestMatcher xmlDigestMatcher : timestampWrapper.getDigestMatchers()) {
                assertTrue(xmlDigestMatcher.isDataFound());
                assertTrue(xmlDigestMatcher.isDataIntact());

                if (DigestMatcherType.MESSAGE_IMPRINT == xmlDigestMatcher.getType()) {
                    messageImprintFound = true;
                } else if (DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE == xmlDigestMatcher.getType()) {
                    masterSigDMFound = true;
                } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP == xmlDigestMatcher.getType()) {
                    tstRenewalDMFound = true;
                } else {
                    fail(String.format("Not expected type : '%s'", xmlDigestMatcher.getType()));
                }
            }
            assertTrue(messageImprintFound);

            if (masterSigDMFound) {
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

}
