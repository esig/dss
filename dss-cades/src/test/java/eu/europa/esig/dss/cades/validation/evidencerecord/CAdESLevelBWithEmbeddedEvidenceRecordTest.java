package eu.europa.esig.dss.cades.validation.evidencerecord;

import eu.europa.esig.dss.cades.validation.AbstractCAdESTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CAdESLevelBWithEmbeddedEvidenceRecordTest extends AbstractCAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/C-E-ERS-basic-der.p7m");
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(0);
        assertTrue(digestMatcher.isDataFound());
        assertTrue(digestMatcher.isDataIntact());
        assertFalse(digestMatcher.isDuplicated());

        assertFalse(signatureWrapper.isSignatureIntact());
        assertFalse(signatureWrapper.isSignatureValid());
        assertFalse(diagnosticData.isBLevelTechnicallyValid(signatureWrapper.getId()));
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        // skip
    }

}
