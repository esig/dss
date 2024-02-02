package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Asn1EvidenceRecordGroupOneDocumentValidationTest extends AbstractAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
    	return new FileDocument("src/test/resources/evidencerecord.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
    	return Collections.singletonList(new DigestDocument(DigestAlgorithm.SHA256, "Oida+g+rN0DmsVgqZOgAex7lYghgYcgQth4CXl5idH0="));
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        return false;
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        super.checkEvidenceRecords(diagnosticData);

        EvidenceRecordWrapper evidenceRecord = diagnosticData.getEvidenceRecords().get(0);

        int foundDataObjectCounter = 0;
        int orphanDataObjectsCounter = 0;
        for (XmlDigestMatcher digestMatcher : evidenceRecord.getDigestMatchers()) {
            if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == digestMatcher.getType()) {
                ++foundDataObjectCounter;
            } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == digestMatcher.getType()) {
                ++orphanDataObjectsCounter;
            }
        }
        assertEquals(1, foundDataObjectCounter);
        assertEquals(5, orphanDataObjectsCounter);
    }

}
