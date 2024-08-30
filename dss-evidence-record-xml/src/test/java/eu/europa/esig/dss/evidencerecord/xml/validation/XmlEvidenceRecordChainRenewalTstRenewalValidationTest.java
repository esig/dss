package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.EvidenceRecordTimestampType;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XmlEvidenceRecordChainRenewalTstRenewalValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-chain-renewal-tst-renewal.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new FileDocument("src/test/resources/valid-xades-t.xml"));
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordTimestamps(diagnosticData);

        EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecords().get(0);
        assertNotNull(evidenceRecordWrapper);

        List<TimestampWrapper> timestampList = evidenceRecordWrapper.getTimestampList();
        assertEquals(3, timestampList.size());

        int arcTstCounter = 0;
        int tstRenewalCounter = 0;
        int chainRenewalTstCounter = 0;
        for (TimestampWrapper timestampWrapper : timestampList) {
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureIntact());
            assertTrue(timestampWrapper.isSignatureValid());

            List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
            for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
                assertTrue(xmlDigestMatcher.isDataFound());
                assertTrue(xmlDigestMatcher.isDataIntact());
            }

            if (EvidenceRecordTimestampType.ARCHIVE_TIMESTAMP == timestampWrapper.getEvidenceRecordTimestampType()) {
                ++arcTstCounter;
            } else if (EvidenceRecordTimestampType.TIMESTAMP_RENEWAL_ARCHIVE_TIMESTAMP == timestampWrapper.getEvidenceRecordTimestampType()) {
                ++tstRenewalCounter;
            } else if (EvidenceRecordTimestampType.HASH_TREE_RENEWAL_ARCHIVE_TIMESTAMP == timestampWrapper.getEvidenceRecordTimestampType()) {
                ++chainRenewalTstCounter;
            }
        }
        assertEquals(1, arcTstCounter);
        assertEquals(1, tstRenewalCounter);
        assertEquals(1, chainRenewalTstCounter);
    }

}
