package eu.europa.esig.dss.pades.signature.visible;

import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer.PdfBoxDSSFontMetrics;
import eu.europa.esig.dss.pdf.visible.SignatureFieldDimensionAndPosition;
import eu.europa.esig.dss.pdf.visible.SignatureFieldDimensionAndPositionBuilder;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class SignatureFieldDimensionAndPositionBuilderTest {

    @Test
    public void dss2438Test() throws IOException {
        DSSDocument document = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
        DSSDocument image = new InMemoryDocument(getClass().getResourceAsStream("/signature-pen.png"));

        try (InputStream is = document.openStream()) {
            PDDocument pdDocument = PDDocument.load(is);

            SignatureImageParameters params = new SignatureImageParameters();
            // we pass null as the MIME type to make the test results repeatable
            // regardless of the particular image's DPI
            params.setImage(image);
            params.getFieldParameters().setOriginX(10);
            params.getFieldParameters().setOriginY(20);
            params.getFieldParameters().setWidth(200);
            params.getFieldParameters().setHeight(50);

            params.getTextParameters().setSignerTextPosition(SignerTextPosition.LEFT);
            params.getTextParameters().setText("1234567890");

            PDPage page = pdDocument.getPage(0);
            PDRectangle mediaBox = page.getMediaBox();
            AnnotationBox pageBox = new AnnotationBox(mediaBox.getLowerLeftX(), mediaBox.getLowerLeftY(),
                    mediaBox.getUpperRightX(), mediaBox.getUpperRightY());

            DSSFileFont dssFont = DSSFileFont.initializeDefault();
            PDFont font = PDType0Font.load(pdDocument, dssFont.getInputStream());
            PdfBoxDSSFontMetrics fontMetrics = new PdfBoxDSSFontMetrics(font);

            SignatureFieldDimensionAndPosition dimPos = new SignatureFieldDimensionAndPositionBuilder(
                    params, fontMetrics, pageBox, page.getRotation()).build();
            assertEquals(dimPos.getBoxHeight(), dimPos.getImageBoxY() + dimPos.getImageBoxHeight());
            assertEquals(dimPos.getBoxWidth(), dimPos.getImageBoxX() + dimPos.getImageBoxWidth());

            params.getTextParameters().setSignerTextPosition(SignerTextPosition.BOTTOM);

            dimPos = new SignatureFieldDimensionAndPositionBuilder(
                    params, fontMetrics, pageBox, page.getRotation()).build();
            assertEquals(dimPos.getBoxHeight(), dimPos.getImageBoxY() + dimPos.getImageBoxHeight());
            assertEquals(dimPos.getBoxWidth(), dimPos.getImageBoxX() + dimPos.getImageBoxWidth());

        } catch (Exception e) {
            fail(e);
        }
    }

}
