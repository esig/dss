package eu.europa.esig.dss.pdfa.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.DocumentValidatorFactory;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

/**
 * Loads a PDF/A validator for a PDF document
 *
 */
public class PDFADocumentValidatorFactory implements DocumentValidatorFactory {

    /**
     * Default constructor
     */
    public PDFADocumentValidatorFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        PDFADocumentValidator validator = new PDFADocumentValidator();
        return validator.isSupported(document);
    }

    @Override
    public SignedDocumentValidator create(DSSDocument document) {
        return new PDFADocumentValidator(document);
    }

}
