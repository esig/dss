package eu.europa.esig.dss.pades.signature.extension;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDocumentReader;

import java.io.IOException;

public class PdfBoxLevelBOldPdfDeveloperExtensionTest extends PAdESLevelBOldPdfDeveloperExtensionTest {

    @Override
    protected PdfDocumentReader getDocumentReader(DSSDocument document) throws IOException {
        return new PdfBoxDocumentReader(document);
    }

}
