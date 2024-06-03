package eu.europa.esig.dss.pades.signature.extension;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDocumentReader;

import java.io.IOException;

public class PdfBoxLevelBSha3AndEdDSAPdf17DeveloperExtensionTest extends PAdESLevelBSha3AndEdDSAPdf17DeveloperExtensionTest {

    @Override
    protected PdfDocumentReader getDocumentReader(DSSDocument document) throws IOException {
        return new PdfBoxDocumentReader(document);
    }

}