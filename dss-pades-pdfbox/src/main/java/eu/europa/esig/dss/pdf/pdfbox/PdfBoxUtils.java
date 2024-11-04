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
package eu.europa.esig.dss.pdf.pdfbox;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pdf.PdfMemoryUsageSetting;
import eu.europa.esig.dss.pdf.pdfbox.util.PdfBoxPageDocumentRequest;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.signature.resources.DSSResourcesHandler;
import org.apache.pdfbox.io.MemoryUsageSetting;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.Objects;

/**
 * Contains a set of utils for PdfBox implementation
 *
 */
public class PdfBoxUtils {

	private PdfBoxUtils() {
	}
	
	/**
	 * Generates a screenshot image of the specified page for the given PDF document
	 * 
	 * @param pdfBoxPageDocumentRequest {@link PdfBoxPageDocumentRequest}
	 * @return {@link DSSDocument} PNG screenshot
	 */
	public static DSSDocument generateScreenshot(PdfBoxPageDocumentRequest pdfBoxPageDocumentRequest) {
		return generateScreenshot(pdfBoxPageDocumentRequest, PAdESUtils.initializeDSSResourcesHandler());
	}
	
	/**
	 * Generates a screenshot image of the specified page for the given PDF document
	 * 
	 * @param pdfBoxPageDocumentRequest {@link PdfBoxPageDocumentRequest}
	 * @param dssResourcesHandler {@link DSSResourcesHandler}
	 * @return {@link DSSDocument} PNG screenshot
	 */
	public static DSSDocument generateScreenshot(PdfBoxPageDocumentRequest pdfBoxPageDocumentRequest, DSSResourcesHandler dssResourcesHandler) {
		Objects.requireNonNull(pdfBoxPageDocumentRequest, "pageDocumentRequest shall be defined!");
		BufferedImage bufferedImage = PdfBoxUtils.generateBufferedImageScreenshot(pdfBoxPageDocumentRequest);
		return ImageUtils.toDSSDocument(bufferedImage, dssResourcesHandler);
	}
	
	/**
	 * The method generates a BufferedImage for the specified page of the document
	 *
	 * @param pdfBoxPageDocumentRequest {@link PdfBoxPageDocumentRequest}
	 * @return {@link BufferedImage}
	 */
	public static BufferedImage generateBufferedImageScreenshot(PdfBoxPageDocumentRequest pdfBoxPageDocumentRequest) {
		Objects.requireNonNull(pdfBoxPageDocumentRequest, "pageDocumentRequest shall be defined!");
		try (PdfBoxDocumentReader reader = new PdfBoxDocumentReader(pdfBoxPageDocumentRequest.getPdfDocument(), pdfBoxPageDocumentRequest.getPasswordProtection() != null ? new String(pdfBoxPageDocumentRequest.getPasswordProtection()) : null,
				pdfBoxPageDocumentRequest.getPdfMemoryUsageSetting())) {
			return reader.generateImageScreenshot(pdfBoxPageDocumentRequest.getPage());
		} catch (IOException e) {
			throw new DSSException(
					String.format("Unable to generate a screenshot for the document with name '%s' " + "for the page number '%s'. Reason : %s", pdfBoxPageDocumentRequest.getPdfDocument().getName(), pdfBoxPageDocumentRequest.getPage(), e.getMessage()),
					e);
		}
	}	

	/**
	 * This method returns an image representing a subtraction result between
	 * {@code pdfBoxPageDocumentRequest1} and {@code pdfBoxPageDocumentRequest2} for the defined pages
	 *
	 * @param pdfBoxPageDocumentRequest1 {@link PdfBoxPageDocumentRequest} the first document request
	 * @param pdfBoxPageDocumentRequest2 {@link PdfBoxPageDocumentRequest} the second document request
	 * @return {@link DSSDocument} subtraction result
	 */
	public static DSSDocument generateSubtractionImage(PdfBoxPageDocumentRequest pdfBoxPageDocumentRequest1, PdfBoxPageDocumentRequest pdfBoxPageDocumentRequest2) {
		return generateSubtractionImage(pdfBoxPageDocumentRequest1, pdfBoxPageDocumentRequest2, PAdESUtils.initializeDSSResourcesHandler());
	}

	/**
	 * This method returns an image representing a subtraction result between
	 * {@code pdfBoxPageDocumentRequest1} and {@code pdfBoxPageDocumentRequest2} for the defined
	 * pages.
	 * <p>
	 * This method uses a provided {@code DSSResourcesHandler}
	 *
	 * @param pdfBoxPageDocumentRequest1 {@link PdfBoxPageDocumentRequest} the first document
	 *                             request
	 * @param pdfBoxPageDocumentRequest2 {@link PdfBoxPageDocumentRequest} the second document
	 *                             request
	 * @param dssResourcesHandler  {@link DSSResourcesHandler} to be used
	 * @return {@link DSSDocument} subtraction result
	 */
	public static DSSDocument generateSubtractionImage(PdfBoxPageDocumentRequest pdfBoxPageDocumentRequest1, PdfBoxPageDocumentRequest pdfBoxPageDocumentRequest2, DSSResourcesHandler dssResourcesHandler) {
		BufferedImage screenshotDoc1 = generateBufferedImageScreenshot(pdfBoxPageDocumentRequest1);
		BufferedImage screenshotDoc2 = generateBufferedImageScreenshot(pdfBoxPageDocumentRequest2);

		int width = Math.max(screenshotDoc1.getWidth(), screenshotDoc2.getWidth());
		int height = Math.max(screenshotDoc1.getHeight(), screenshotDoc2.getHeight());

		BufferedImage outputImage = getOutputImage(width, height);
		ImageUtils.drawSubtractionImage(screenshotDoc1, screenshotDoc2, outputImage);

		return ImageUtils.toDSSDocument(outputImage, dssResourcesHandler);
	}

	private static BufferedImage getOutputImage(int width, int height) {
		BufferedImage outputImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
		Graphics2D drawer = outputImage.createGraphics();
		drawer.setBackground(Color.WHITE);
		drawer.clearRect(0, 0, width, height);
		return outputImage;
	}

	/**
	 * This method creates a generic Appearance dictionary, containing a Normal
	 * Appearance
	 *
	 * @param pdDocument  {@link PDDocument} to create a new Appearance dictionary
	 *                    in
	 * @param pdRectangle {@link PDRectangle} used for annotation dictionary
	 * @return {@link PDAppearanceDictionary}
	 */
	public static PDAppearanceDictionary createSignatureAppearanceDictionary(PDDocument pdDocument,
			PDRectangle pdRectangle) {
		Objects.requireNonNull(pdDocument, "PDDocument cannot be null!");
		Objects.requireNonNull(pdRectangle, "PDRectangle cannot be null!");

		PDStream stream = new PDStream(pdDocument);
		PDFormXObject form = new PDFormXObject(stream);
		PDResources res = new PDResources();
		form.setResources(res);
		form.setFormType(1);

		// create a copy of rectangle
		form.setBBox(new PDRectangle(pdRectangle.getWidth(), pdRectangle.getHeight()));

		PDAppearanceDictionary appearance = new PDAppearanceDictionary();
		appearance.getCOSObject().setDirect(true);
		PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
		appearance.setNormalAppearance(appearanceStream);

		return appearance;
	}

	/**
	 * It converts generic {@link PdfMemoryUsageSetting} to PDF Box domain
	 * 
	 * @param pdfMemoryUsageSetting {@link PdfMemoryUsageSetting}
	 * @return {@link MemoryUsageSetting}
	 */
	public static MemoryUsageSetting getMemoryUsageSetting(PdfMemoryUsageSetting pdfMemoryUsageSetting) {
		switch (pdfMemoryUsageSetting.getMode()) {
			case MEMORY_FULL:
				return MemoryUsageSetting.setupMainMemoryOnly(); // no limitations applicable
			case MEMORY_BUFFERED:
				return MemoryUsageSetting.setupMainMemoryOnly(pdfMemoryUsageSetting.getMaxMemoryBytes());
			case FILE:
				return MemoryUsageSetting.setupTempFileOnly(pdfMemoryUsageSetting.getMaxStorageBytes());
			case MIXED:
				return MemoryUsageSetting.setupMixed(pdfMemoryUsageSetting.getMaxMemoryBytes(), pdfMemoryUsageSetting.getMaxStorageBytes());
			default:
				throw new UnsupportedOperationException(String.format(
						"The MemoryUsageSetting mode '%s' is not supported!", pdfMemoryUsageSetting.getMode()));
			}
	}

}
