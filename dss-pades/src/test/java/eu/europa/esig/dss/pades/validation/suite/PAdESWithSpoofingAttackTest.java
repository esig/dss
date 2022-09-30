package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class PAdESWithSpoofingAttackTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/pdf-spoofing-attack.pdf"));
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
