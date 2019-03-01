package eu.europa.esig.dss.pades;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;

public class PdfScreenshotUtils {

	private static final Logger LOG = LoggerFactory.getLogger(PdfScreenshotUtils.class);

	// https://stackoverflow.com/questions/25022578/highlight-differences-between-images
	public static BufferedImage getDifferenceImage(DSSDocument dssDoc1, DSSDocument dssDoc2) throws IOException {
		BufferedImage img1 = getRendering(dssDoc1);
		BufferedImage img2 = getRendering(dssDoc2);
		if (areEqualSize(img1, img2)) {
			BufferedImage outImg = new BufferedImage(img1.getWidth(), img1.getHeight(), BufferedImage.TYPE_INT_RGB);
			drawSubstractionImage(img1, img2, outImg);
			return outImg;
		}
		return null;
	}
	
	public static boolean areVisuallyEqual(DSSDocument dssDoc1, DSSDocument dssDoc2) throws IOException {
		BufferedImage img1 = getRendering(dssDoc1);
		BufferedImage img2 = getRendering(dssDoc2);
		if (areEqualSize(img1, img2)) {
			BufferedImage outImg = new BufferedImage(img1.getWidth(), img1.getHeight(), BufferedImage.TYPE_INT_RGB);
			int diffAmount = drawSubstractionImage(img1, img2, outImg);
			return diffAmount == 0;
		}
		return false;
	}

	private static BufferedImage getRendering(DSSDocument dssDoc) throws IOException {
		try (InputStream is = dssDoc.openStream(); PDDocument doc = PDDocument.load(is)) {
			PDFRenderer renderer = new PDFRenderer(doc);
			return renderer.renderImage(0);
		}
	}
	
	private static boolean areEqualSize(BufferedImage img1, BufferedImage img2) {
		if ((img1.getWidth() != img2.getWidth()) || (img1.getHeight() != img2.getHeight())) {
			LOG.error("Error: Images dimensions mismatch");
			return false;
		}
		return true;
	}
	
	private static int drawSubstractionImage(BufferedImage img1, BufferedImage img2, BufferedImage outImg) {
		int diffAmount = 0;
		// Modified - Changed to int as pixels are ints
		int diff;
		int result; // Stores output pixel
		for (int i = 0; i < img1.getHeight(); i++) {
			for (int j = 0; j < img1.getWidth(); j++) {
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
				if (diff > 0) 
					diffAmount++;
			}
		}
		return diffAmount;
	}
	
}
