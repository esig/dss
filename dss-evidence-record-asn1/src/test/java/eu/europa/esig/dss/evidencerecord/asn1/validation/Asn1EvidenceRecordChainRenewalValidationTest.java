package eu.europa.esig.dss.evidencerecord.asn1.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

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

public class Asn1EvidenceRecordChainRenewalValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
    	return new FileDocument("src/test/resources/ER-2Chains3ATS.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
    	return Arrays.asList(
    			new InMemoryDocument("content of data object DO-01".getBytes(), "ER-2Chains3ATS1.bin")
    			// the ER doesn't cover the second document in the second chain
//    			,new InMemoryDocument("content of data object DO-02".getBytes(), "ER-2Chains3ATS2.bin")
    			);
    }
    
    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordTimestamps(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        List<XmlSignatureScope> evidenceRecordScopes = evidenceRecordWrapper.getEvidenceRecordScopes();
        assertEquals(1, evidenceRecordScopes.size());

        assertEquals(2, diagnosticData.getTimestampList().size());

        boolean initialTstFound = false;
        boolean chainRenewalTstFound = false;
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
            if (digestMatchers.size() == 1) {
                assertEquals(DigestMatcherType.MESSAGE_IMPRINT, digestMatchers.get(0).getType());
                initialTstFound = true;
            } else if (digestMatchers.size() == 3) {
                boolean messageImprintFound = false;
                boolean archiveDataObjectFound = false;
                boolean previousChainFound = false;
                for (XmlDigestMatcher digestMatcher : digestMatchers) {
                    if (DigestMatcherType.MESSAGE_IMPRINT == digestMatcher.getType()) {
                        messageImprintFound = true;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == digestMatcher.getType()) {
                        archiveDataObjectFound = true;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE == digestMatcher.getType()) {
                        previousChainFound = true;
                    }
                }
                assertTrue(messageImprintFound);
                assertTrue(archiveDataObjectFound);
                assertTrue(previousChainFound);

                List<XmlSignatureScope> timestampScopes = timestampWrapper.getTimestampScopes();
                assertEquals(1, timestampScopes.size());
                assertEquals(evidenceRecordScopes.get(0).getSignerData(), timestampScopes.get(0).getSignerData());

                chainRenewalTstFound = true;
            }
        }
        assertTrue(initialTstFound);
        assertTrue(chainRenewalTstFound);
    }

}
