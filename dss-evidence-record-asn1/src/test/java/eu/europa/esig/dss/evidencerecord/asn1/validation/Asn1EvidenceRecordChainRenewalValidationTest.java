package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class Asn1EvidenceRecordChainRenewalValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
    	return new FileDocument("src/test/resources/ER-2Chains3ATS.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
    	return Arrays.asList(new InMemoryDocument("content of data object DO-01".getBytes(), "ER-2Chains3ATS1.bin"));
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        // the ER doesn't cover the second document in the second chain
        // new InMemoryDocument("content of data object DO-02".getBytes(), "ER-2Chains3ATS2.bin")
        return false;
    }

    @Override
    protected boolean tstCoversOnlyCurrentHashTreeData() {
        // ArchiveTimeStamp covers also two additional data objects
        return false;
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordTimestamps(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        List<XmlSignatureScope> evidenceRecordScopes = evidenceRecordWrapper.getEvidenceRecordScopes();
        assertEquals(1, evidenceRecordScopes.size());

        assertEquals(3, diagnosticData.getTimestampList().size());

        boolean initialTstFound = false;
        boolean renewalTstFound = false;
        boolean chainRenewalTstFound = false;
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            int messageImprintCounter = 0;
            int archiveDataObjectCounter = 0;
            int orphanRefsCounter = 0;
            int archiveTimeStampCounter = 0;
            int previousChainCounter = 0;

            List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
            for (XmlDigestMatcher digestMatcher : digestMatchers) {
                if (DigestMatcherType.MESSAGE_IMPRINT == digestMatcher.getType()) {
                    ++messageImprintCounter;
                } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == digestMatcher.getType()) {
                    ++archiveDataObjectCounter;
                } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == digestMatcher.getType()) {
                    ++orphanRefsCounter;
                } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP == digestMatcher.getType()) {
                    ++archiveTimeStampCounter;
                } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE == digestMatcher.getType()) {
                    ++previousChainCounter;
                }
            }

            if (digestMatchers.size() == 1) {
                assertEquals(1, messageImprintCounter);
                initialTstFound = true;

            } else if (digestMatchers.size() == 4) {
                assertEquals(1, messageImprintCounter);
                assertEquals(0, archiveDataObjectCounter);
                assertEquals(2, orphanRefsCounter);
                assertEquals(1, archiveTimeStampCounter);
                assertEquals(0, previousChainCounter);

                List<XmlSignatureScope> timestampScopes = timestampWrapper.getTimestampScopes();
                assertEquals(1, timestampScopes.size());
                assertEquals(evidenceRecordScopes.get(0).getSignerData(), timestampScopes.get(0).getSignerData());

                renewalTstFound = true;

            } else if (digestMatchers.size() == 3) {
                assertEquals(1, messageImprintCounter);
                assertEquals(0, archiveDataObjectCounter);
                assertEquals(1, orphanRefsCounter);
                assertEquals(0, archiveTimeStampCounter);
                assertEquals(1, previousChainCounter);

                List<XmlSignatureScope> timestampScopes = timestampWrapper.getTimestampScopes();
                assertEquals(1, timestampScopes.size());
                assertEquals(evidenceRecordScopes.get(0).getSignerData(), timestampScopes.get(0).getSignerData());

                chainRenewalTstFound = true;
            }
        }
        assertTrue(initialTstFound);
        assertTrue(renewalTstFound);
        assertTrue(chainRenewalTstFound);
    }

}
