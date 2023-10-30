package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class Asn1EvidenceRecordInvalidRefValidationValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/BIN-1_ER.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Arrays.asList(
                new DigestDocument(DigestAlgorithm.SHA256, "odTntQ2Wk/mjGy6UhOpq36WFg3cw/iupTROl1MgcMt8=", "some binary content"),
                new DigestDocument(DigestAlgorithm.SHA256, "t+btFtQajsHkMsByflnnYdSUwKbYnlRhV4rVJsoiw2o=", "some invalid binary content")
        );
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);

        List<ReferenceValidation> referenceValidations = evidenceRecord.getReferenceValidation();
        assertEquals(2, referenceValidations.size());

        int foundDocCounter = 0;
        int notFoundDocCounter = 0;
        for (ReferenceValidation referenceValidation : referenceValidations) {
            if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == referenceValidation.getType()) {
                assertTrue(referenceValidation.isFound());
                assertTrue(referenceValidation.isIntact());
                assertEquals("some binary content", referenceValidation.getName());
                ++foundDocCounter;
            } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == referenceValidation.getType()) {
                assertFalse(referenceValidation.isFound());
                assertFalse(referenceValidation.isIntact());
                ++notFoundDocCounter ;
            }
        }
        assertEquals(1, foundDocCounter);
        assertEquals(1, notFoundDocCounter);
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecords().get(0);

        int foundDocCounter = 0;
        int notFoundDocCounter = 0;
        for (XmlDigestMatcher digestMatcher : evidenceRecordWrapper.getDigestMatchers()) {
            if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == digestMatcher.getType()) {
                assertTrue(digestMatcher.isDataFound());
                assertTrue(digestMatcher.isDataIntact());
                assertEquals("some binary content", digestMatcher.getName());
                ++foundDocCounter;
            } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == digestMatcher.getType()) {
                assertFalse(digestMatcher.isDataFound());
                assertFalse(digestMatcher.isDataIntact());
                ++notFoundDocCounter ;
            }
        }
        assertEquals(1, foundDocCounter);
        assertEquals(1, notFoundDocCounter);
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordScopes(diagnosticData);

        EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecords().get(0);
        List<XmlSignatureScope> evidenceRecordScopes = evidenceRecordWrapper.getEvidenceRecordScopes();
        assertEquals(1, evidenceRecordScopes.size());

        assertNotNull(evidenceRecordScopes.get(0).getSignerData());
        assertEquals(SignatureScopeType.FULL, evidenceRecordScopes.get(0).getScope());
        assertEquals("some binary content", evidenceRecordScopes.get(0).getName());
        assertEquals("Full document", evidenceRecordScopes.get(0).getDescription());
    }

}
