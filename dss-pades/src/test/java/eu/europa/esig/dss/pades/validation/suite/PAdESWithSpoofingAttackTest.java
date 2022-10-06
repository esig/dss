package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESWithSpoofingAttackTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/pdf-spoofing-attack.pdf"));
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        XmlPDFRevision pdfRevision = signature.getPDFRevision();
        assertNotNull(pdfRevision);
        assertTrue(Utils.isCollectionNotEmpty(pdfRevision.getFields()));
        checkPdfSignatureDictionary(pdfRevision.getPDFSignatureDictionary());

        assertFalse(signature.arePdfModificationsDetected());
        assertFalse(Utils.isCollectionEmpty(signature.getPdfUndefinedChanges()));
    }

    @Override
    protected void checkPdfSignatureDictionary(XmlPDFSignatureDictionary pdfSignatureDictionary) {
        assertNotNull(pdfSignatureDictionary);
        assertNotNull(pdfSignatureDictionary.getType());
        assertNotNull(pdfSignatureDictionary.getSubFilter());
        checkByteRange(pdfSignatureDictionary.getSignatureByteRange());
        assertFalse(pdfSignatureDictionary.isConsistent());
    }

}
