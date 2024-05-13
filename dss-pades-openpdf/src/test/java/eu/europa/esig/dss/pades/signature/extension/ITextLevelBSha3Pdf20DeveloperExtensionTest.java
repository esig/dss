package eu.europa.esig.dss.pades.signature.extension;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.openpdf.ITextDocumentReader;

import java.io.IOException;

public class ITextLevelBSha3Pdf20DeveloperExtensionTest extends PAdESLevelBSha3Pdf20DeveloperExtensionTest {

    @Override
    protected PdfDocumentReader getDocumentReader(DSSDocument document) throws IOException {
        return new ITextDocumentReader(document);
    }

}
