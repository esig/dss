package eu.europa.esig.dss.pades.signature.visible;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.openpdf.ITextDefaultPdfObjFactory;
import eu.europa.esig.dss.pdfa.signature.visible.suite.PDFAVisibleSignatureTest;
import org.junit.jupiter.api.Test;

import java.io.IOException;

public class ITextPDFAVisibleSignatureTest extends PDFAVisibleSignatureTest {

    @Override
    protected void setCustomFactory() {
        service.setPdfObjFactory(new ITextDefaultPdfObjFactory());
    }

    @Test
    public void testAddCMYKImageToRGBDoc() throws IOException {
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/pdfa2a-rgb.pdf"));

        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/cmyk.jpg"), "cmyk.jpg", MimeTypeEnum.JPEG));

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(100);
        fieldParameters.setOriginY(100);
        imageParameters.setFieldParameters(fieldParameters);

        signatureParameters.setImageParameters(imageParameters);

        signAndValidate("PDF/A-2A", true);
    }

}
