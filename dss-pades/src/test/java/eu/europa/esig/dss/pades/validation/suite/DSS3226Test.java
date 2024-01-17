package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class DSS3226Test extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/DSS-3226.pdf"));
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();

        DefaultPdfObjectModificationsFinder pdfObjectModificationsFinder = new DefaultPdfObjectModificationsFinder();
        pdfObjectModificationsFinder.setLaxNumericComparison(true);
        pdfObjFactory.setPdfObjectModificationsFinder(pdfObjectModificationsFinder);

        PDFDocumentValidator validator = (PDFDocumentValidator) super.getValidator(signedDocument);
        validator.setPdfObjFactory(pdfObjFactory);

        return validator;
    }

}
