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
package eu.europa.esig.dss.pdf.pdfbox.visible;

import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.visible.DSSFontMetrics;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.pdf.visible.SignatureFieldBoxBuilder;
import eu.europa.esig.dss.pdf.visible.SignatureFieldDimensionAndPosition;
import eu.europa.esig.dss.pdf.visible.SignatureFieldDimensionAndPositionBuilder;
import eu.europa.esig.dss.utils.Utils;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.graphics.color.PDOutputIntent;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.color.ColorSpace;
import java.awt.color.ICC_Profile;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;

/**
 * The abstract implementation of PDFBox signature drawer
 *
 */
public abstract class AbstractPdfBoxSignatureDrawer implements PdfBoxSignatureDrawer, SignatureFieldBoxBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractPdfBoxSignatureDrawer.class);

	/** Visual signature parameters */
	protected SignatureImageParameters parameters;

	/** The PDF document */
	protected PDDocument document;

	/** Contains options of the visual signature */
	protected SignatureOptions signatureOptions;

	/**
	 * Default constructor instantiating object with null values
	 */
	protected AbstractPdfBoxSignatureDrawer() {
	}

	@Override
	public void init(SignatureImageParameters parameters, PDDocument document, SignatureOptions signatureOptions) throws IOException {
		assertSignatureParametersAreValid(parameters);
		this.parameters = parameters;
		this.document = document;
		this.signatureOptions = signatureOptions;
		checkColorSpace(document);
	}
	
	private void assertSignatureParametersAreValid(SignatureImageParameters parameters) {
		if (parameters == null || parameters.getImage() == null && parameters.getTextParameters().isEmpty()) {
			throw new IllegalArgumentException("Neither image nor text parameters are defined!");
		}
	}
	
	/**
	 * Builds a signature field dimension and position object
	 *
	 * @return {@link SignatureFieldDimensionAndPosition}
	 */
	public SignatureFieldDimensionAndPosition buildSignatureFieldBox() {
		PDPage originalPage = document.getPage(parameters.getFieldParameters().getPage() - ImageUtils.DEFAULT_FIRST_PAGE);
		PDRectangle mediaBox = originalPage.getMediaBox();
		AnnotationBox pageBox = new AnnotationBox(mediaBox.getLowerLeftX(), mediaBox.getLowerLeftY(),
				mediaBox.getUpperRightX(), mediaBox.getUpperRightY());
		return new SignatureFieldDimensionAndPositionBuilder(parameters, getDSSFontMetrics(), pageBox,
				originalPage.getRotation()).setSignatureFieldAnnotationBox(getSignatureFieldAnnotationBox()).build();
	}

	/**
	 * Gets the corresponding {@code eu.europa.esig.dss.pdf.visible.DSSFontMetrics}
	 *
	 * @return {@link eu.europa.esig.dss.pdf.visible.DSSFontMetrics}
	 */
	protected abstract DSSFontMetrics getDSSFontMetrics();

	/**
	 * Method to check if the target image's color space is present in the document's catalog
	 * 
	 * @param pdDocument {@link PDDocument} to check color profiles in
	 * @throws IOException in case of image reading error
	 */
	protected void checkColorSpace(PDDocument pdDocument) throws IOException {
		if (!parameters.isEmpty()) {
	        PDDocumentCatalog catalog = pdDocument.getDocumentCatalog();
	        List<PDOutputIntent> profiles = catalog.getOutputIntents();
			String colorSpaceName = getExpectedColorSpaceName();
	        if (Utils.isCollectionEmpty(profiles)) {
				addColorSpace(catalog, colorSpaceName);

	        } else if (profiles.size() > 1) {
				LOG.warn("PDF contains multiple color spaces. Be aware: not compatible with PDF/A.");

			} else {
				if (COSName.DEVICECMYK.getName().equals(colorSpaceName) && !isProfilePresent(profiles, ImageUtils.CMYK_PROFILE_NAME)) {
					LOG.warn("PDF does not contain a CMYK profile! Be aware: not compatible with PDF/A.");
				} else if (COSName.DEVICERGB.getName().equals(colorSpaceName) && !isProfilePresent(profiles, ImageUtils.RGB_PROFILE_NAME)) {
					LOG.warn("PDF does not contain an RGB profile! Be aware: not compatible with PDF/A.");
				}
				// GRAY profile is supported by RGB and CMYK
			}

		}
	}
	
	/**
	 * Returns color space name for the provided image
	 *
	 * @return {@link String} color space name
	 * @throws IOException in case of image reading error
	 */
	protected abstract String getExpectedColorSpaceName() throws IOException;

	/**
	 * This method is used to add a new required color space to a document
	 *
	 * @param catalog {@link PDDocumentCatalog} from a PDF document to add a new color space into
	 * @param colorSpaceName {@link String} a color space name to add
	 */
	protected void addColorSpace(PDDocumentCatalog catalog, String colorSpaceName) {
		// sRGB supports both RGB and Grayscale color spaces
		if (COSName.DEVICERGB.getName().equals(colorSpaceName) || COSName.DEVICEGRAY.getName().equals(colorSpaceName)) {
			int colorSpace = ColorSpace.CS_sRGB;
			String outputCondition = ImageUtils.OUTPUT_INTENT_SRGB_PROFILE;

			ICC_Profile iccProfile = ICC_Profile.getInstance(colorSpace);
			try (InputStream is = new ByteArrayInputStream(iccProfile.getData())) {
				PDOutputIntent outputIntent = new PDOutputIntent(document, is);
				outputIntent.setOutputCondition(outputCondition);
				outputIntent.setOutputConditionIdentifier(outputCondition);
				catalog.setOutputIntents(Collections.singletonList(outputIntent));

				LOG.info("No color profile is present in the provided document. " +
						"A new color profile '{}' has been added.", outputCondition);

			} catch (IOException e) {
				LOG.warn("Unable to add a new color profile to PDF document : {}", e.getMessage(), e);
			}

		} else {
			LOG.warn("Color space '{}' is not supported. Be aware: the produced PDF may be not compatible with PDF/A.",
					colorSpaceName);
		}
	}
	
	private boolean isProfilePresent(List<PDOutputIntent> profiles, String profileName) {
        for (PDOutputIntent profile : profiles) {
            if (Utils.isStringNotEmpty(profile.getInfo()) && 
            		profile.getInfo().toLowerCase().contains(profileName) ||
                Utils.isStringNotEmpty(profile.getOutputCondition()) && 
                	profile.getOutputCondition().toLowerCase().contains(profileName) ||
                Utils.isStringNotEmpty(profile.getOutputConditionIdentifier()) && 
                	profile.getOutputConditionIdentifier().toLowerCase().contains(profileName)) {
                return true;
            }
        }
        return false;
	}

	private AnnotationBox getSignatureFieldAnnotationBox() {
		PDSignatureField signatureField = getExistingSignatureFieldToFill();
		if (signatureField != null) {
			List<PDAnnotationWidget> widgets = signatureField.getWidgets();
			if (Utils.isCollectionNotEmpty(widgets)) {
				PDAnnotationWidget pdAnnotationWidget = widgets.get(0);
				if (pdAnnotationWidget != null) {
					PDRectangle rectangle = pdAnnotationWidget.getRectangle();
					return new AnnotationBox(rectangle.getLowerLeftX(), rectangle.getLowerLeftY(),
							rectangle.getUpperRightX(), rectangle.getUpperRightY());
				}
			}

		}
		return null;
	}

	private PDSignatureField getExistingSignatureFieldToFill() {
		String signatureFieldId = parameters.getFieldParameters().getFieldId();
		if (Utils.isStringNotEmpty(signatureFieldId)) {
			PDAcroForm acroForm = document.getDocumentCatalog().getAcroForm();
			if (acroForm != null) {
				PDSignatureField signatureField = (PDSignatureField) acroForm.getField(signatureFieldId);
				if (signatureField != null) {
					return signatureField;
				}
			}
		}
		return null;
	}

}
