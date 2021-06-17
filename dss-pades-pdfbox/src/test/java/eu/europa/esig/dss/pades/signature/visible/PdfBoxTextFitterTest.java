package eu.europa.esig.dss.pades.signature.visible;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer.PdfBoxDSSFontMetrics;
import eu.europa.esig.dss.pdf.visible.DSSFontMetrics;
import eu.europa.esig.dss.pdf.visible.TextFitter;
import java.io.IOException;
import java.util.stream.Stream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 *
 * @author bnazare
 */
public class PdfBoxTextFitterTest {

	private static final DSSFileFont DEFAULT_SIG_FONT = DSSFileFont.initializeDefault();

	private static final String[] DEFAULT_LINES = new String[]{
		"Digitally signed by JOHN GEORGE ANTHONY WILLIAMS",
		"Date: 2021.01.01 01:01:01 WET",
		"Reason: my-reason",
		"Location: my-location"
	};

	public PdfBoxTextFitterTest() {
	}

	private void testFitSignatureText(float width, float height, TextFitter fitter, boolean expectedFitted, float expectedFontSize, String expectedWrappedText) throws IllegalStateException {
		AnnotationBox textDimensions = new AnnotationBox(0, 0, width, height);
		TextFitter.Result fitResult;
		try (PDDocument doc = new PDDocument()) {
			// stream will be closed in method
			PDFont font = PDType0Font.load(doc, DEFAULT_SIG_FONT.getInputStream());
			DSSFontMetrics fontMetrics = new PdfBoxDSSFontMetrics(font);
			fitResult = fitter.fitSignatureText(DEFAULT_LINES, fontMetrics, textDimensions);
		} catch (IOException ex) {
			throw new IllegalStateException(ex);
		}

		assertEquals(expectedFitted, fitResult.isFitted());
		assertEquals(expectedFontSize, fitResult.getSize());
		assertEquals(expectedWrappedText, fitResult.getText());
	}

	@ParameterizedTest
	@MethodSource
	public void testFitSignatureText(float width, float height, boolean expectedFitted, float expectedFontSize, String expectedWrappedText) throws Exception {
		TextFitter fitter = new TextFitter();
		testFitSignatureText(width, height, fitter, expectedFitted, expectedFontSize, expectedWrappedText);
	}

	@ParameterizedTest
	@MethodSource
	public void testFitSignatureText_FewMaxLines(float width, float height, boolean expectedFitted, float expectedFontSize, String expectedWrappedText) throws Exception {
		TextFitter fitter = new TextFitter(2, false);
		testFitSignatureText(width, height, fitter, expectedFitted, expectedFontSize, expectedWrappedText);
	}

	@ParameterizedTest
	@MethodSource
	public void testFitSignatureText_AllowOverflow(float width, float height, boolean expectedFitted, float expectedFontSize, String expectedWrappedText) throws Exception {
		TextFitter fitter = new TextFitter(20, true);
		testFitSignatureText(width, height, fitter, expectedFitted, expectedFontSize, expectedWrappedText);
	}

	static Stream<Arguments> testFitSignatureText() {
		return Stream.of(
			arguments(75, 60, true, 6.722689f, "Digitally signed by JOHN\nGEORGE ANTHONY\nWILLIAMS\n"
				+ "Date: 2021.01.01\n01:01:01 WET\n"
				+ "Reason: my-reason\n"
				+ "Location: my-location"),
			arguments(150, 60, true, 9.411765f, "Digitally signed by JOHN GEORGE\nANTHONY WILLIAMS\n"
				+ "Date: 2021.01.01 01:01:01 WET\n"
				+ "Reason: my-reason\n"
				+ "Location: my-location"),
			arguments(300, 60, true, 11.764706f, "Digitally signed by JOHN GEORGE ANTHONY WILLIAMS\n"
				+ "Date: 2021.01.01 01:01:01 WET\n"
				+ "Reason: my-reason\n"
				+ "Location: my-location"),
			arguments(30, 60, true, 3.9215686f, "Digitally signed\nby JOHN\nGEORGE\nANTHONY\nWILLIAMS\n"
				+ "Date: 2021.01.01\n01:01:01 WET\n"
				+ "Reason:\nmy-reason\n"
				+ "Location:\nmy-location"),
			arguments(75, 30, true, 4.7058825f, "Digitally signed by JOHN GEORGE\nANTHONY WILLIAMS\n"
				+ "Date: 2021.01.01 01:01:01 WET\n"
				+ "Reason: my-reason\n"
				+ "Location: my-location"),
			arguments(10, 60, false, -1, null)
		);
	}

	static Stream<Arguments> testFitSignatureText_FewMaxLines() {
		return Stream.of(
			arguments(75, 60, false, -1, null),
			arguments(150, 60, true, 9.411765f, "Digitally signed by JOHN GEORGE\nANTHONY WILLIAMS\n"
				+ "Date: 2021.01.01 01:01:01 WET\n"
				+ "Reason: my-reason\n"
				+ "Location: my-location"),
			arguments(300, 60, true, 11.764706f, "Digitally signed by JOHN GEORGE ANTHONY WILLIAMS\n"
				+ "Date: 2021.01.01 01:01:01 WET\n"
				+ "Reason: my-reason\n"
				+ "Location: my-location"),
			arguments(30, 60, false, -1, null),
			arguments(75, 30, true, 4.7058825f, "Digitally signed by JOHN GEORGE\nANTHONY WILLIAMS\n"
				+ "Date: 2021.01.01 01:01:01 WET\n"
				+ "Reason: my-reason\n"
				+ "Location: my-location"),
			arguments(10, 60, false, -1, null)
		);
	}

	static Stream<Arguments> testFitSignatureText_AllowOverflow() {
		return Stream.of(
			arguments(75, 60, true, 6.722689f, "Digitally signed by JOHN\nGEORGE ANTHONY\nWILLIAMS\n"
				+ "Date: 2021.01.01\n01:01:01 WET\n"
				+ "Reason: my-reason\n"
				+ "Location: my-location"),
			arguments(150, 60, true, 9.411765f, "Digitally signed by JOHN GEORGE\nANTHONY WILLIAMS\n"
				+ "Date: 2021.01.01 01:01:01 WET\n"
				+ "Reason: my-reason\n"
				+ "Location: my-location"),
			arguments(300, 60, true, 11.764706f, "Digitally signed by JOHN GEORGE ANTHONY WILLIAMS\n"
				+ "Date: 2021.01.01 01:01:01 WET\n"
				+ "Reason: my-reason\n"
				+ "Location: my-location"),
			arguments(30, 60, true, 3.9215686f, "Digitally signed\nby JOHN\nGEORGE\nANTHONY\nWILLIAMS\n"
				+ "Date: 2021.01.01\n01:01:01 WET\n"
				+ "Reason:\nmy-reason\n"
				+ "Location:\nmy-location"),
			arguments(75, 30, true, 4.7058825f, "Digitally signed by JOHN GEORGE\nANTHONY WILLIAMS\n"
				+ "Date: 2021.01.01 01:01:01 WET\n"
				+ "Reason: my-reason\n"
				+ "Location: my-location"),
			arguments(10, 60, true, 3.137255f, "Digitally\nsigned\nby\nJOHN\nGEORGE\nANTHONY\nWILLIAMS\n"
				+ "Date:\n2021.01.01\n01:01:01\nWET\n"
				+ "Reason:\nmy-reason\n"
				+ "Location:\nmy-location")
		);
	}

}
