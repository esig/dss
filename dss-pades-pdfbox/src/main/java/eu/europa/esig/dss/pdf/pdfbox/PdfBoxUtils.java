package eu.europa.esig.dss.pdf.pdfbox;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.rendering.PDFRenderer;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Objects;

/**
 * Contains a set of utils for PdfBox implementation
 *
 */
public class PdfBoxUtils {

	/** The default name for a screenshot document */
	private static final String SCREENSHOT_PNG_NAME = "screenshot.png";

	private PdfBoxUtils() {
	}

	/**
	 * Generates a screenshot image of the specified page for the given PDF document
	 * 
	 * @param pdfDocument {@link DSSDocument} to generate screenshot for
	 * @param page        a page number
	 * @return {@link DSSDocument} PNG screenshot
	 */
	public static DSSDocument generateScreenshot(DSSDocument pdfDocument, int page) {
		return generateScreenshot(pdfDocument, null, page);
	}

	/**
	 * Generates a screenshot image of the specified page for the given PDF document
	 * 
	 * @param pdfDocument        {@link DSSDocument} to generate screenshot for
	 * @param passwordProtection {@link String} a PDF password protection phrase
	 * @param page               a page number
	 * @return {@link DSSDocument} PNG screenshot
	 */
	public static DSSDocument generateScreenshot(DSSDocument pdfDocument, String passwordProtection, int page) {
		BufferedImage bufferedImage = generateBufferedImageScreenshot(pdfDocument, passwordProtection, page);
		return toDSSDocument(bufferedImage);
	}

	/**
	 * The method generates a BufferedImage for the specified page of the document
	 * 
	 * @param pdfDocument        {@link DSSDocument} to generate screenshot for
	 * @param passwordProtection {@link String} a PDF password protection phrase
	 * @param page               a page number to be generates (starts from 1)
	 * @return {@link BufferedImage}
	 */
	public static BufferedImage generateBufferedImageScreenshot(DSSDocument pdfDocument, String passwordProtection,
			int page) {
		Objects.requireNonNull(pdfDocument, "pdfDocument shall be defined!");
		try (PdfBoxDocumentReader reader = new PdfBoxDocumentReader(pdfDocument, passwordProtection)) {
			return reader.generateImageScreenshot(page);
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to generate a screenshot for the document with name '%s' "
					+ "for the page number '%s'. Reason : %s", pdfDocument.getName(), page, e.getMessage()), e);
		}
	}

	/**
	 * The method generates a BufferedImage for the specified page of the document
	 * 
	 * @param pdDocument {@link PDDocument} to generate screenshot for
	 * @param page       a page number to be generates (starts from 1)
	 * @return {@link BufferedImage}
	 * @throws IOException if an exception occurs
	 */
	public static BufferedImage generateBufferedImageScreenshot(PDDocument pdDocument, int page) throws IOException {
		PDFRenderer renderer = new PDFRenderer(pdDocument);
		return renderer.renderImage(page - ImageUtils.DEFAULT_FIRST_PAGE);
	}

	/**
	 * This method returns an image representing a subtraction result between
	 * {@code document1} and {@code document2} for the given page number
	 * 
	 * @param document1 {@link DSSDocument}
	 * @param document2 {@link DSSDocument}
	 * @param page      page number
	 * @return {@link DSSDocument} subtraction result
	 */
	public static DSSDocument generateSubtractionImage(DSSDocument document1, DSSDocument document2, int page) {
		return generateSubtractionImage(document1, null, page, document2, null, page);
	}

	/**
	 * This method returns an image representing a subtraction result between
	 * {@code document1} and {@code document2} for the defined pages
	 * 
	 * @param document1         {@link DSSDocument} the first document
	 * @param passwordDocument1 {@link String} a password protection for the
	 *                          {@code document1} when applicable (can be null)
	 * @param pageDocument1     page number identifying a page of the
	 *                          {@code document1} to be proceeded
	 * @param document2         {@link DSSDocument} the second document
	 * @param passwordDocument2 {@link String} a password protection for the
	 *                          {@code document2} when applicable (can be null)
	 * @param pageDocument2     page number identifying a page of the
	 *                          {@code document2} to be proceeded
	 * @return {@link DSSDocument} subtraction result
	 */
	public static DSSDocument generateSubtractionImage(DSSDocument document1, String passwordDocument1,
			int pageDocument1, DSSDocument document2, String passwordDocument2, int pageDocument2) {
		BufferedImage screenshotDoc1 = generateBufferedImageScreenshot(document1, passwordDocument1, pageDocument1);
		BufferedImage screenshotDoc2 = generateBufferedImageScreenshot(document2, passwordDocument2, pageDocument2);

		int width = Math.max(screenshotDoc1.getWidth(), screenshotDoc2.getWidth());
		int height = Math.max(screenshotDoc1.getHeight(), screenshotDoc2.getHeight());

		BufferedImage outputImage = getOutputImage(width, height);
		ImageUtils.drawSubtractionImage(screenshotDoc1, screenshotDoc2, outputImage);

		return toDSSDocument(outputImage);
	}

	private static BufferedImage getOutputImage(int width, int height) {
		BufferedImage outputImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
		Graphics2D drawer = outputImage.createGraphics();
		drawer.setBackground(Color.WHITE);
		drawer.clearRect(0, 0, width, height);
		return outputImage;
	}

	/**
	 * Transforms a {@code BufferedImage} to {@code DSSDocument}
	 * 
	 * @param bufferedImage {@link BufferedImage} to convert
	 * @return {@link DSSDocument}
	 */
	private static DSSDocument toDSSDocument(BufferedImage bufferedImage) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			ImageIO.write(bufferedImage, "png", baos);
			return new InMemoryDocument(baos.toByteArray(), SCREENSHOT_PNG_NAME, MimeType.PNG);
		} catch (IOException e) {
			throw new DSSException(
					String.format("Unable to convert BufferedImage to DSSDocument. Reason : %s", e.getMessage()), e);
		}
	}

}
