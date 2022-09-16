package eu.europa.esig.dss.pades.signature.visible;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.openpdf.ITextDefaultPdfObjFactory;
import eu.europa.esig.dss.pdfa.signature.visible.suite.PDFAVisibleSignatureTest;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.IOException;

// TODO : disabled due to OpenPdf issues (see PR #814, #815)
@Disabled
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

    @Test
    public void testAddGrayscalePNGImageToGrayColorSpaceDoc() throws IOException {
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/pdfa2a-gray.pdf"));

        SignatureImageParameters imageParameters = new SignatureImageParameters();
        // iText does not support PNG-grayscale images
        imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/grayscale_image.png"), "grayscale_image.png", MimeTypeEnum.PNG));

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(100);
        fieldParameters.setOriginY(100);
        fieldParameters.setWidth(100);
        fieldParameters.setHeight(150);
        imageParameters.setFieldParameters(fieldParameters);

        signatureParameters.setImageParameters(imageParameters);

        // iText does not support PNG-grayscale
        signAndValidate("PDF/A-2A", false);
    }

}
