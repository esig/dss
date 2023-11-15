package eu.europa.esig.dss.asic.xades.validation.evidencerecord;

import eu.europa.esig.dss.asic.common.validation.AbstractASiCWithEvidenceRecordTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCSWithXAdESEvidenceRecordValidationTest extends AbstractASiCWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/er-one-file.scs");
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordDigestMatchers(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        List<XmlDigestMatcher> digestMatchers = evidenceRecords.get(0).getDigestMatchers();
        assertEquals(2, digestMatchers.size());

        boolean coveredFileFound = false;
        boolean notCoveredFileFound = false;
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            if (digestMatcher.isDataFound()) {
                assertEquals(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT, digestMatcher.getType());
                assertEquals("test.zip", digestMatcher.getName());
                assertNotNull(digestMatcher.getDigestMethod());
                assertNotNull(digestMatcher.getDigestValue());
                assertTrue(digestMatcher.isDataIntact());
                coveredFileFound = true;
            } else {
                assertEquals(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE, digestMatcher.getType());
                assertNull(digestMatcher.getName());
                assertNotNull(digestMatcher.getDigestMethod());
                assertNotNull(digestMatcher.getDigestValue());
                assertFalse(digestMatcher.isDataIntact());
                notCoveredFileFound = true;
            }
        }
        assertTrue(coveredFileFound);
        assertTrue(notCoveredFileFound);
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        return false;
    }

}
