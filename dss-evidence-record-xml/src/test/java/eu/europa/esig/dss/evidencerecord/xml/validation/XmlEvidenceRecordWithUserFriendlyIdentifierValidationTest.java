package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.validation.UserFriendlyIdentifierProvider;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class XmlEvidenceRecordWithUserFriendlyIdentifierValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-simple.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new DigestDocument(DigestAlgorithm.SHA256, "qC9i7yNq1pZCzScV+ya3oBVRR9Y92gnDdYWTCQ8nstU="));
    }

    @Override
    protected TokenIdentifierProvider getTokenIdentifierProvider() {
        return new UserFriendlyIdentifierProvider();
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        super.checkEvidenceRecords(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        assertEquals("EVIDENCE-RECORD_Symantec-SHA256-TimeStamping-Signer-G3_20211006-0128", evidenceRecordWrapper.getId());
    }

}
