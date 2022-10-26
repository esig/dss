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
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.signature.resources.DSSResourcesHandler;
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
	 * @param pdfDocument {@link DSSDocument} to generate screenshot for
	 * @param page        a page number
	 * @return {@link DSSDocument} PNG screenshot
	 */
	public static DSSDocument generateScreenshot(DSSDocument pdfDocument, int page) {
		return generateScreenshot(pdfDocument, (byte[]) null, page);
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
		return generateScreenshot(pdfDocument, passwordProtection, page, PAdESUtils.initializeDSSResourcesHandler());
	}

	/**
	 * Generates a screenshot image of the specified page for the given PDF document
	 *
	 * @param pdfDocument        {@link DSSDocument} to generate screenshot for
	 * @param passwordProtection a PDF password protection phrase
	 * @param page               a page number
	 * @return {@link DSSDocument} PNG screenshot
	 */
	public static DSSDocument generateScreenshot(DSSDocument pdfDocument, byte[] passwordProtection, int page) {
		return generateScreenshot(pdfDocument, passwordProtection, page, PAdESUtils.initializeDSSResourcesHandler());
	}

	/**
	 * Generates a screenshot image of the specified page for the given PDF document using a provided
	 * {@code eu.europa.esig.dss.signature.resources.DSSResourcesHandler}
	 *
	 * @param pdfDocument        {@link DSSDocument} to generate screenshot for
	 * @param passwordProtection {@link String} a PDF password protection phrase
	 * @param page               a page number
	 * @param dssResourcesHandler {@link DSSResourcesHandler}
	 * @return {@link DSSDocument} PNG screenshot
	 */
	public static DSSDocument generateScreenshot(DSSDocument pdfDocument, String passwordProtection, int page,
												 DSSResourcesHandler dssResourcesHandler) {
		BufferedImage bufferedImage = generateBufferedImageScreenshot(pdfDocument, passwordProtection, page);
		return ImageUtils.toDSSDocument(bufferedImage, dssResourcesHandler);
	}

	/**
	 * Generates a screenshot image of the specified page for the given PDF document using a provided
	 * {@code eu.europa.esig.dss.signature.resources.DSSResourcesHandler}
	 *
	 * @param pdfDocument         {@link DSSDocument} to generate screenshot for
	 * @param passwordProtection  {@link String} a PDF password protection phrase
	 * @param page                a page number
	 * @param dssResourcesHandler {@link DSSResourcesHandler}
	 * @return {@link DSSDocument} PNG screenshot
	 */
	public static DSSDocument generateScreenshot(DSSDocument pdfDocument, byte[] passwordProtection, int page,
												 DSSResourcesHandler dssResourcesHandler) {
		BufferedImage bufferedImage = generateBufferedImageScreenshot(pdfDocument, passwordProtection, page);
		return ImageUtils.toDSSDocument(bufferedImage, dssResourcesHandler);
	}

	/**
	 * The method generates a BufferedImage for the specified page of the document with String password
	 * 
	 * @param pdfDocument        {@link DSSDocument} to generate screenshot for
	 * @param passwordProtection {@link String} a PDF password protection phrase
	 * @param page               a page number to be generates (starts from 1)
	 * @return {@link BufferedImage}
	 */
	public static BufferedImage generateBufferedImageScreenshot(DSSDocument pdfDocument, String passwordProtection,
			int page) {
		return generateBufferedImageScreenshot(pdfDocument, passwordProtection != null ?
				passwordProtection.getBytes() : null, page);
	}

	/**
	 * The method generates a BufferedImage for the specified page of the document
	 *
	 * @param pdfDocument        {@link DSSDocument} to generate screenshot for
	 * @param passwordProtection a PDF password protection phrase
	 * @param page               a page number to be generates (starts from 1)
	 * @return {@link BufferedImage}
	 */
	public static BufferedImage generateBufferedImageScreenshot(DSSDocument pdfDocument, byte[] passwordProtection,
																int page) {
		Objects.requireNonNull(pdfDocument, "pdfDocument shall be defined!");
		try (PdfBoxDocumentReader reader = new PdfBoxDocumentReader(
				pdfDocument, passwordProtection != null ? new String(passwordProtection) : null)) {
			return reader.generateImageScreenshot(page);
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to generate a screenshot for the document with name '%s' "
					+ "for the page number '%s'. Reason : %s", pdfDocument.getName(), page, e.getMessage()), e);
		}
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
		return generateSubtractionImage(document1, (byte[]) null, page, document2, (byte[]) null, page);
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
	public static DSSDocument generateSubtractionImage(DSSDocument document1, String passwordDocument1, int pageDocument1,
													   DSSDocument document2, String passwordDocument2, int pageDocument2) {
		return generateSubtractionImage(document1, passwordDocument1, pageDocument1,
				document2, passwordDocument2, pageDocument2, PAdESUtils.initializeDSSResourcesHandler());
	}

	/**
	 * This method returns an image representing a subtraction result between
	 * {@code document1} and {@code document2} for the defined pages
	 *
	 * @param document1         {@link DSSDocument} the first document
	 * @param passwordDocument1 a password protection for the
	 *                          {@code document1} when applicable (can be null)
	 * @param pageDocument1     page number identifying a page of the
	 *                          {@code document1} to be proceeded
	 * @param document2         {@link DSSDocument} the second document
	 * @param passwordDocument2 a password protection for the
	 *                          {@code document2} when applicable (can be null)
	 * @param pageDocument2     page number identifying a page of the
	 *                          {@code document2} to be proceeded
	 * @return {@link DSSDocument} subtraction result
	 */
	public static DSSDocument generateSubtractionImage(DSSDocument document1, byte[] passwordDocument1, int pageDocument1,
													   DSSDocument document2, byte[] passwordDocument2, int pageDocument2) {
		return generateSubtractionImage(document1, passwordDocument1, pageDocument1,
				document2, passwordDocument2, pageDocument2, PAdESUtils.initializeDSSResourcesHandler());
	}

	/**
	 * This method returns an image representing a subtraction result between
	 * {@code document1} and {@code document2} for the defined pages.
	 * This method uses a provided {@code DSSResourcesHandler}
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
	 * @param dssResourcesHandler {@link DSSResourcesHandler} to be used
	 * @return {@link DSSDocument} subtraction result
	 */
	public static DSSDocument generateSubtractionImage(DSSDocument document1, String passwordDocument1, int pageDocument1,
													   DSSDocument document2, String passwordDocument2, int pageDocument2,
													   DSSResourcesHandler dssResourcesHandler) {
		return generateSubtractionImage(document1, passwordDocument1 != null ? passwordDocument1.getBytes() : null, pageDocument1,
				document2, passwordDocument2 != null ? passwordDocument2.getBytes() : null, pageDocument2, dssResourcesHandler);
	}

	/**
	 * This method returns an image representing a subtraction result between
	 * {@code document1} and {@code document2} for the defined pages.
	 * This method uses a provided {@code DSSResourcesHandler}
	 *
	 * @param document1         {@link DSSDocument} the first document
	 * @param passwordDocument1 a password protection for the
	 *                          {@code document1} when applicable (can be null)
	 * @param pageDocument1     page number identifying a page of the
	 *                          {@code document1} to be proceeded
	 * @param document2         {@link DSSDocument} the second document
	 * @param passwordDocument2 a password protection for the
	 *                          {@code document2} when applicable (can be null)
	 * @param pageDocument2     page number identifying a page of the
	 *                          {@code document2} to be proceeded
	 * @param dssResourcesHandler {@link DSSResourcesHandler} to be used
	 * @return {@link DSSDocument} subtraction result
	 */
	public static DSSDocument generateSubtractionImage(DSSDocument document1, byte[] passwordDocument1, int pageDocument1,
													   DSSDocument document2, byte[] passwordDocument2, int pageDocument2,
													   DSSResourcesHandler dssResourcesHandler) {
		BufferedImage screenshotDoc1 = generateBufferedImageScreenshot(document1, passwordDocument1, pageDocument1);
		BufferedImage screenshotDoc2 = generateBufferedImageScreenshot(document2, passwordDocument2, pageDocument2);

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
	 * This method creates a generic Appearance dictionary, containing a Normal Appearance
	 *
	 * @param pdDocument {@link PDDocument} to create a new Appearance dictionary in
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

}
