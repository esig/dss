package eu.europa.esig.dss.pades.signature.extension;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDocumentReader;

import java.io.IOException;

public class PdfBoxLevelT17PdfDeveloperExtensionTest extends PAdESLevelT17PdfDeveloperExtensionTest {

    @Override
    protected PdfDocumentReader getDocumentReader(DSSDocument document) throws IOException {
        return new PdfBoxDocumentReader(document);
    }

}
