/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPageTree;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;

public class PdfScreenshotUtils {

	private static final Logger LOG = LoggerFactory.getLogger(PdfScreenshotUtils.class);
	
	/**
	 * Comparison resolution: step in pixels in horizontal and vertical directions.
	 */
	private static final int CHECK_RESOLUTION = 1;
	
	private static final int DPI = 144;

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
	
	public static void checkPdfSimilarity(PDDocument document1, PDDocument document2, float minSimilarity) throws IOException {
		PDPageTree samplePageTree = document1.getPages();
		PDPageTree checkPageTree = document2.getPages();

		assertEquals(checkPageTree.getCount(), samplePageTree.getCount());

		PDFRenderer sampleRenderer = new PDFRenderer(document1);
		PDFRenderer checkRenderer = new PDFRenderer(document2);

		for (int pageNumber = 0; pageNumber < checkPageTree.getCount(); pageNumber++) {
			BufferedImage sampleImage = sampleRenderer.renderImageWithDPI(pageNumber, DPI);
			BufferedImage checkImage = checkRenderer.renderImageWithDPI(pageNumber, DPI);
			
            // ImageIO.write(sampleImage, "png", new File("target\\sampleImage.png"));
            // ImageIO.write(checkImage, "png", new File("target\\checkImage.png"));
            
			float checkSimilarity = checkImageSimilarity(sampleImage, checkImage, CHECK_RESOLUTION);
			assertTrue(checkSimilarity >= minSimilarity, "The image similarity " + checkSimilarity + " is lower the allowed limit " + minSimilarity);
		}
	}
	
	public static float checkImageSimilarity(BufferedImage sampleImage, BufferedImage checkImage, int resolution) {
		try {
			int width = sampleImage.getWidth();
			int height = sampleImage.getHeight();
			int checkWidth = checkImage.getWidth();
			int checkHeight = checkImage.getHeight();
			if (width == 0 || height == 0 || checkWidth == 0 || checkHeight == 0) {
				fail(String.format("invalid image size: sample(%dx%d) vs check(%dx%d)", width, height, checkWidth, checkHeight));
			}
			if (width != checkWidth || height != checkHeight) {
				fail(String.format("images size not equal: sample(%dx%d) vs check(%dx%d)", width, height, checkWidth, checkHeight));
			}

			int matchingPixels = 0;
			int checkedPixels = 0;
			for (int y = 0; y < height; y += resolution) {
				for (int x = 0; x < width; x += resolution) {
					int sampleRGB = sampleImage.getRGB(x, y);
					int checkRGB = checkImage.getRGB(x, y);

					if (sampleRGB == checkRGB) {
						matchingPixels++;
					} else {
						checkImage.setRGB(x, y, Color.RED.getRGB());
					}

					checkedPixels++;
				}
			}

			return (float) matchingPixels / checkedPixels;
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}
	
}
