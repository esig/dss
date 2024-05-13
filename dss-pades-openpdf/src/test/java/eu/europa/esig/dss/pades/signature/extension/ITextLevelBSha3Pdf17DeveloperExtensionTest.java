package eu.europa.esig.dss.pades.signature.extension;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.openpdf.ITextDocumentReader;

import java.io.IOException;

public class ITextLevelBSha3Pdf17DeveloperExtensionTest extends PAdESLevelBSha3Pdf17DeveloperExtensionTest {

    @Override
    protected PdfDocumentReader getDocumentReader(DSSDocument document) throws IOException {
        return new ITextDocumentReader(document);
    }

}
