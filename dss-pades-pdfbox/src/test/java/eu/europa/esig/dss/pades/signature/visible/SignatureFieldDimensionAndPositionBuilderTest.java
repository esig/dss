/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.io.RandomAccessRead;
import org.apache.pdfbox.io.RandomAccessReadBuffer;
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

class SignatureFieldDimensionAndPositionBuilderTest {

    @Test
    void dss2438Test() throws IOException {
        DSSDocument document = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
        DSSDocument image = new InMemoryDocument(getClass().getResourceAsStream("/signature-pen.png"));

        try (InputStream is = document.openStream();
             RandomAccessRead rar = new RandomAccessReadBuffer(is);
             PDDocument pdDocument = Loader.loadPDF(rar)) {

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
