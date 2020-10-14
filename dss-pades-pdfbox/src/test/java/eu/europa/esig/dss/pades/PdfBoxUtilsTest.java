package eu.europa.esig.dss.pades;

import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxUtils;

public class PdfBoxUtilsTest {

	private final String correctProtectionPhrase = " ";
	private final String wrongProtectionPhrase = "AAAA";

	private DSSDocument sampleDocument;
	private DSSDocument protectedDocument;
	private DSSDocument twoPagesDocument;

	@BeforeEach
	public void init() {
		sampleDocument = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
		protectedDocument = new InMemoryDocument(getClass().getResourceAsStream("/protected/open_protected.pdf"),
				"sample.pdf", MimeType.PDF);
		twoPagesDocument = new InMemoryDocument(getClass().getResourceAsStream("/empty-two-pages.pdf"));
	}

	@Test
	public void generateScreenshotTest() {
		DSSDocument screenshot = PdfBoxUtils.generateScreenshot(sampleDocument, 1);
		assertNotNull(screenshot);

		Exception exception = assertThrows(IllegalStateException.class,
				() -> PdfBoxUtils.generateScreenshot(sampleDocument, 0));
		assertEquals("1-based index not found: 0", exception.getMessage());

		exception = assertThrows(IndexOutOfBoundsException.class,
				() -> PdfBoxUtils.generateScreenshot(sampleDocument, 2));
		assertEquals("1-based index out of bounds: 2", exception.getMessage());

		exception = assertThrows(NullPointerException.class, () -> PdfBoxUtils.generateScreenshot(null, 1));
		assertEquals("pdfDocument shall be defined!", exception.getMessage());
	}

	@Test
	public void generateScreenshotWithPassTest() {
		DSSDocument screenshot = PdfBoxUtils.generateScreenshot(protectedDocument, correctProtectionPhrase, 1);
		assertNotNull(screenshot);

		Exception exception = assertThrows(DSSException.class,
				() -> PdfBoxUtils.generateScreenshot(protectedDocument, wrongProtectionPhrase, 1));
		assertEquals("Cannot decrypt PDF, the password is incorrect", exception.getMessage());

		exception = assertThrows(DSSException.class, () -> PdfBoxUtils.generateScreenshot(protectedDocument, 1));
		assertEquals("Cannot decrypt PDF, the password is incorrect", exception.getMessage());
	}

	@Test
	public void generateSubtractionImageTest() {
		DSSDocument subtractionImage = PdfBoxUtils.generateSubtractionImage(sampleDocument, null, 1, protectedDocument,
				correctProtectionPhrase, 1);
		assertNotNull(subtractionImage);

		subtractionImage = PdfBoxUtils.generateSubtractionImage(twoPagesDocument, null, 1, twoPagesDocument, null, 2);
		assertNotNull(subtractionImage);

		subtractionImage = PdfBoxUtils.generateSubtractionImage(sampleDocument, twoPagesDocument, 1);
		assertNotNull(subtractionImage);

		Exception exception = assertThrows(IndexOutOfBoundsException.class,
				() -> PdfBoxUtils.generateSubtractionImage(sampleDocument, twoPagesDocument, 2));
		assertEquals("1-based index out of bounds: 2", exception.getMessage());
	}

}
