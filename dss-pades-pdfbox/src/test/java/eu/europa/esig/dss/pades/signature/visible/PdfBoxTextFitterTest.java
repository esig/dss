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

import eu.europa.esig.dss.enumerations.TextWrapping;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxNativeFont;
import eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer.PdfBoxDSSFontMetrics;
import eu.europa.esig.dss.pdf.visible.DSSFontMetrics;
import eu.europa.esig.dss.pdf.visible.TextFitter;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 *
 * @author bnazare
 */
class PdfBoxTextFitterTest {

	private static final DSSFileFont DEFAULT_SIG_FONT = DSSFileFont.initializeDefault();

	private static final String DEFAULT_LINES =
		"Digitally signed by JOHN GEORGE ANTHONY WILLIAMS\n" +
		"Date: 2021.01.01 01:01:01 WET\n" +
		"Reason: my-reason\n" +
		"Location: my-location";

	public PdfBoxTextFitterTest() {
	}

	static Stream<Arguments> testFitSignatureText() {
		return Stream.of(
				arguments(75, 60, "Digitally signed by\nJOHN GEORGE\nANTHONY WILLIAMS\n"
						+ "Date: 2021.01.01\n01:01:01 WET\n"
						+ "Reason: my-reason\n"
						+ "Location: my-location"),
				arguments(150, 60,  "Digitally signed by JOHN\nGEORGE ANTHONY WILLIAMS\n"
						+ "Date: 2021.01.01 01:01:01 WET\n"
						+ "Reason: my-reason\n"
						+ "Location: my-location"),
				arguments(300, 60, "Digitally signed by JOHN GEORGE ANTHONY WILLIAMS\n"
						+ "Date: 2021.01.01 01:01:01 WET\n"
						+ "Reason: my-reason\n"
						+ "Location: my-location"),
				arguments(30, 60, "Digitally signed\nby JOHN\nGEORGE\nANTHONY\nWILLIAMS\n"
						+ "Date:\n2021.01.01\n01:01:01 WET\n"
						+ "Reason:\nmy-reason\n"
						+ "Location:\nmy-location"),
				arguments(75, 30, "Digitally signed by JOHN\nGEORGE ANTHONY WILLIAMS\n"
						+ "Date: 2021.01.01 01:01:01 WET\n"
						+ "Reason: my-reason\n"
						+ "Location: my-location")
		);
	}

	@ParameterizedTest
	@MethodSource
	void testFitSignatureText(float width, float height, String expectedWrappedText) throws Exception {
		AnnotationBox textDimensions = new AnnotationBox(0, 0, width, height);
		TextFitter.Result fitResult;
		try (PDDocument doc = new PDDocument()) {
			// stream will be closed in method
			PDFont font = PDType0Font.load(doc, DEFAULT_SIG_FONT.getInputStream());
			DSSFontMetrics fontMetrics = new PdfBoxDSSFontMetrics(font);
			SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
			textParameters.setText(DEFAULT_LINES);
			textParameters.setFont(new PdfBoxNativeFont(font));
			textParameters.setTextWrapping(TextWrapping.FILL_BOX_AND_LINEBREAK);
			fitResult = TextFitter.fitSignatureText(textParameters, textParameters.getFont().getSize(), fontMetrics, textDimensions);
		} catch (IOException ex) {
			throw new IllegalStateException(ex);
		}
		assertEquals(expectedWrappedText, fitResult.getText());
	}

}
