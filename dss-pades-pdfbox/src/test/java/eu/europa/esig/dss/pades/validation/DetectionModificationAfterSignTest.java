package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import javax.imageio.ImageIO;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class DetectionModificationAfterSignTest {

	private static final Logger LOG = LoggerFactory.getLogger(DetectionModificationAfterSignTest.class);

	@Test
	public void testWithModification() throws IOException {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/modified_after_signature.pdf");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());

		AdvancedSignature advancedSignature = signatures.get(0);

		List<DSSDocument> retrievedDocuments = validator.getOriginalDocuments(advancedSignature.getId());
		assertEquals(1, retrievedDocuments.size());
		DSSDocument retrievedDocument = retrievedDocuments.get(0);

		DSSDocument expected = new FileDocument("src/test/resources/validation/retrieved-modified_after_signature.pdf");
		assertEquals(expected.getDigest(DigestAlgorithm.SHA256), retrievedDocument.getDigest(DigestAlgorithm.SHA256));

		// Additional code to detect visual difference

		BufferedImage renderingDssDocument = getRendering(dssDocument);
		BufferedImage renderingRetrievedDocument = getRendering(retrievedDocument);

		BufferedImage differenceImage = getDifferenceImage(renderingDssDocument, renderingRetrievedDocument);
		ImageIO.write(differenceImage, "PNG", new File("target/diff.png"));
	}

	private BufferedImage getRendering(DSSDocument dssDoc) throws IOException {
		try (InputStream is = dssDoc.openStream(); PDDocument doc = PDDocument.load(is)) {
			PDFRenderer renderer = new PDFRenderer(doc);
			return renderer.renderImage(0);
		}
	}

	// https://stackoverflow.com/questions/25022578/highlight-differences-between-images
	private BufferedImage getDifferenceImage(BufferedImage img1, BufferedImage img2) {
		int width1 = img1.getWidth(); // Change - getWidth() and getHeight() for BufferedImage
		int width2 = img2.getWidth(); // take no arguments
		int height1 = img1.getHeight();
		int height2 = img2.getHeight();
		if ((width1 != width2) || (height1 != height2)) {
			LOG.error("Error: Images dimensions mismatch");
			return null;
		}

		BufferedImage outImg = new BufferedImage(width1, height1, BufferedImage.TYPE_INT_RGB);

		// Modified - Changed to int as pixels are ints
		int diff;
		int result; // Stores output pixel
		for (int i = 0; i < height1; i++) {
			for (int j = 0; j < width1; j++) {
				int rgb1 = img1.getRGB(j, i);
				int rgb2 = img2.getRGB(j, i);
				int r1 = (rgb1 >> 16) & 0xff;
				int g1 = (rgb1 >> 8) & 0xff;
				int b1 = (rgb1) & 0xff;
				int r2 = (rgb2 >> 16) & 0xff;
				int g2 = (rgb2 >> 8) & 0xff;
				int b2 = (rgb2) & 0xff;
				diff = Math.abs(r1 - r2); // Change
				diff += Math.abs(g1 - g2);
				diff += Math.abs(b1 - b2);
				diff /= 3; // Change - Ensure result is between 0 - 255
				// Make the difference image gray scale
				// The RGB components are all the same
				result = (diff << 16) | (diff << 8) | diff;
				outImg.setRGB(j, i, result); // Set result
			}
		}

		return outImg;
	}

}
