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
package eu.europa.esig.dss.pades.signature.visible;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDocumentReader;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxUtils;
import eu.europa.esig.dss.pdf.pdfbox.util.PdfBoxPageDocumentRequest;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.test.PKIFactoryAccess;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageTree;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.rendering.PDFRenderer;

import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractTestVisualComparator extends PKIFactoryAccess {

	/**
	 * Comparison resolution: step in pixels in horizontal and vertical directions.
	 */
	private static final int CHECK_RESOLUTION = 1;

	private static final int DPI = 144;

	/**
	 * The degree of similarity between generated and original images
	 */
	private static final float DEFAULT_SIMILARITY_LIMIT = 0.995f;

	protected abstract String getTestName();

	protected abstract PAdESService getService();

	protected abstract DSSDocument getDocumentToSign();

	protected abstract PAdESSignatureParameters getSignatureParameters();

	protected void drawAndCompareVisually() throws IOException {
		getService().setPdfObjFactory(new PdfBoxDefaultObjectFactory());
		DSSDocument defaultDrawerPdf = sign(getTestName() + "_default");
		getService().setPdfObjFactory(new PdfBoxNativeObjectFactory());
		DSSDocument nativeDrawerPdf = sign(getTestName() + "_native");
		compareVisualSimilarity(defaultDrawerPdf, nativeDrawerPdf);
		compareAnnotations(defaultDrawerPdf, nativeDrawerPdf);
	}

	protected void drawAndCompareExplicitly() throws IOException {
		getService().setPdfObjFactory(new PdfBoxDefaultObjectFactory());
		DSSDocument defaultDrawerPdf = sign("default");

		getService().setPdfObjFactory(new PdfBoxNativeObjectFactory());
		DSSDocument nativeDrawerPdf = sign("native");

		compareAnnotations(defaultDrawerPdf, nativeDrawerPdf);
		compareVisualSimilarity(defaultDrawerPdf, nativeDrawerPdf);
		assertTrue(arePdfDocumentsVisuallyEqual(defaultDrawerPdf, nativeDrawerPdf));

		DSSDocument previewNative = getService().previewPageWithVisualSignature(getDocumentToSign(), getSignatureParameters());
		DSSDocument signatureFieldNative = getService().previewSignatureField(getDocumentToSign(), getSignatureParameters());
		
		assertFalse(areImagesVisuallyEqual(previewNative, PdfBoxUtils.generateScreenshot(new PdfBoxPageDocumentRequest(getDocumentToSign(), 1))));
		assertFalse(areImagesVisuallyEqual(previewNative, signatureFieldNative));
		assertTrue(areImagesVisuallyEqual(previewNative, PdfBoxUtils.generateScreenshot(new PdfBoxPageDocumentRequest(nativeDrawerPdf, 1))));
	}

	protected boolean arePdfDocumentsVisuallyEqual(DSSDocument dssDoc1, DSSDocument dssDoc2) throws IOException {
		return compareBufferedImages(getScreenshotWithDpi(dssDoc1), getScreenshotWithDpi(dssDoc2));
	}

	private BufferedImage getScreenshotWithDpi(DSSDocument dssDoc) throws IOException {
		try (InputStream is = dssDoc.openStream(); PDDocument doc = PDDocument.load(is)) {
			PDFRenderer renderer = new PDFRenderer(doc);
			return renderer.renderImageWithDPI(0, DPI);
		}
	}

	protected boolean areImagesVisuallyEqual(DSSDocument dssImage1, DSSDocument dssImage2) throws IOException {
		return compareBufferedImages(toBufferedImage(dssImage1), toBufferedImage(dssImage2));
	}

	private BufferedImage toBufferedImage(DSSDocument dssImageDocument) {
		try (InputStream is = dssImageDocument.openStream()) {
			return ImageIO.read(is);
		} catch (Exception e) {
			fail(e);
			return null;
		}
	}

	private boolean compareBufferedImages(BufferedImage img1, BufferedImage img2) {
		if (ImageUtils.imageDimensionsEqual(img1, img2)) {
			BufferedImage outImg = new BufferedImage(img1.getWidth(), img1.getHeight(), BufferedImage.TYPE_INT_RGB);
			int diffAmount = ImageUtils.drawSubtractionImage(img1, img2, outImg);
			return diffAmount == 0;
		}
		return false;
	}

	protected DSSDocument sign(String docName) throws IOException {
		ToBeSigned dataToSign = getService().getDataToSign(getDocumentToSign(), getSignatureParameters());
		SignatureValue signatureValue = getToken().sign(dataToSign, getSignatureParameters().getDigestAlgorithm(),
				getPrivateKeyEntry());
		DSSDocument document = getService().signDocument(getDocumentToSign(), getSignatureParameters(), signatureValue);
		// document.save("target/" + docName + ".pdf");
		return document;
	}

	protected void compareAnnotations(DSSDocument doc1, DSSDocument doc2) throws IOException {
		try (PdfBoxDocumentReader reader1 = new PdfBoxDocumentReader(doc1);
				PdfBoxDocumentReader reader2 = new PdfBoxDocumentReader(doc2);) {
			assertEquals(reader1.getNumberOfPages(), reader2.getNumberOfPages());
			for (int i = 1; i <= reader1.getNumberOfPages(); i++) {
				PDPage page1 = reader1.getPDPage(i);
				PDPage page2 = reader2.getPDPage(i);
				assertEquals(page1.getRotation(), page2.getRotation());
				assertEquals(page1.getAnnotations().size(), page2.getAnnotations().size());
				for (int j = 0; j < page1.getAnnotations().size(); j++) {
					PDRectangle rect1 = page1.getAnnotations().get(j).getRectangle();
					PDRectangle rect2 = page2.getAnnotations().get(j).getRectangle();
					// assert max 2% difference, due to different text size computation
					// NOTE: must be non-negative
					assertEquals(rect1.getLowerLeftX(), rect2.getLowerLeftX(), Math.abs(rect1.getLowerLeftX()) / 50);
					assertEquals(rect1.getLowerLeftY(), rect2.getLowerLeftY(), Math.abs(rect1.getLowerLeftY()) / 50);
					assertEquals(rect1.getUpperRightX(), rect2.getUpperRightX(), Math.abs(rect1.getUpperRightX()) / 50);
					assertEquals(rect1.getUpperRightY(), rect2.getUpperRightY(), Math.abs(rect1.getUpperRightY()) / 50);
				}
			}
		}
	}

	protected void compareVisualSimilarity(DSSDocument doc1, DSSDocument doc2) throws IOException {
		compareVisualSimilarity(doc1, doc2, getSimilarityLimit());
	}

	protected float getSimilarityLimit() {
		return DEFAULT_SIMILARITY_LIMIT;
	}

	protected void compareVisualSimilarity(DSSDocument doc1, DSSDocument doc2, float similarityLevel)
			throws IOException {
		try (InputStream is1 = doc1.openStream();
				InputStream is2 = doc2.openStream();
				PDDocument pdDoc1 = PDDocument.load(is1);
				PDDocument pdDoc2 = PDDocument.load(is2);) {
			checkPdfSimilarity(pdDoc1, pdDoc2, similarityLevel);
		}
	}

	protected void checkPdfSimilarity(PDDocument document1, PDDocument document2, float minSimilarity)
			throws IOException {
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
			assertTrue(checkSimilarity >= minSimilarity,
					"The image similarity " + checkSimilarity + " is lower the allowed limit " + minSimilarity);
		}
	}

	protected float checkImageSimilarity(BufferedImage sampleImage, BufferedImage checkImage, int resolution) {
		try {
			int width = sampleImage.getWidth();
			int height = sampleImage.getHeight();
			int checkWidth = checkImage.getWidth();
			int checkHeight = checkImage.getHeight();
			if (width == 0 || height == 0 || checkWidth == 0 || checkHeight == 0) {
				fail(String.format("invalid image size: sample(%dx%d) vs check(%dx%d)", width, height, checkWidth,
						checkHeight));
			}
			if (width != checkWidth || height != checkHeight) {
				fail(String.format("images size not equal: sample(%dx%d) vs check(%dx%d)", width, height, checkWidth,
						checkHeight));
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

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
