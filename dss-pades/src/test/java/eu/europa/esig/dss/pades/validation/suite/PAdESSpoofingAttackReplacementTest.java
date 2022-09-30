package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.enumerations.PdfObjectModificationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESSpoofingAttackReplacementTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/pades-spoofing-replaced-reason.pdf"));
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        XmlPDFRevision pdfRevision = signatureWrapper.getPDFRevision();
        assertNotNull(pdfRevision);
        assertTrue(Utils.isCollectionNotEmpty(pdfRevision.getFields()));
        checkPdfSignatureDictionary(pdfRevision.getPDFSignatureDictionary());

        assertFalse(signatureWrapper.arePdfModificationsDetected());

        List<XmlObjectModification> pdfUndefinedChanges = signatureWrapper.getPdfUndefinedChanges();
        assertEquals(1, pdfUndefinedChanges.size());
        assertEquals(PdfObjectModificationType.MODIFICATION, pdfUndefinedChanges.get(0).getAction());
        assertTrue(pdfUndefinedChanges.get(0).getValue().contains(PAdESConstants.REASON_NAME));
    }

    protected void checkPdfSignatureDictionary(XmlPDFSignatureDictionary pdfSignatureDictionary) {
        assertNotNull(pdfSignatureDictionary);
        assertNotNull(pdfSignatureDictionary.getType());
        assertNotNull(pdfSignatureDictionary.getSubFilter());
        checkByteRange(pdfSignatureDictionary.getSignatureByteRange());
        assertFalse(pdfSignatureDictionary.isConsistent());
    }

}
