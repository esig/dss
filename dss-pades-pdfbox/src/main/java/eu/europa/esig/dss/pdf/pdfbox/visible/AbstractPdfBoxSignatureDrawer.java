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
package eu.europa.esig.dss.pdf.pdfbox.visible;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
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
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;

/**
 * The abstract implementation of PDFBox signature drawer
 */
public abstract class AbstractPdfBoxSignatureDrawer implements PdfBoxSignatureDrawer, SignatureFieldBoxBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractPdfBoxSignatureDrawer.class);

	/** The CMYK color profile */
	private static final String CMYK_PROFILE_NAME = "cmyk";

	/** The RGB color profile */
	private static final String RGB_PROFILE_NAME = "rgb";

	/** Visual signature parameters */
	protected SignatureImageParameters parameters;

	/** The PDF document */
	protected PDDocument document;

	/** Contains options of the visual signature */
	protected SignatureOptions signatureOptions;

	/** Defines signature field dimensions and position */
	private SignatureFieldDimensionAndPosition dimensionAndPosition;

	@Override
	public void init(SignatureImageParameters parameters, PDDocument document, SignatureOptions signatureOptions) throws IOException {
		assertSignatureParametersAreValid(parameters);
		this.parameters = parameters;
		this.document = document;
		this.signatureOptions = signatureOptions;
		checkColorSpace(document, parameters.getImage());
	}
	
	private void assertSignatureParametersAreValid(SignatureImageParameters parameters) {
		if (parameters == null || parameters.getImage() == null && parameters.getTextParameters().isEmpty()) {
			throw new DSSException("Neither image nor text parameters are defined!");
		}
	}
	
	/**
	 * Builds a signature field dimension and position object
	 *
	 * @return {@link SignatureFieldDimensionAndPosition}
	 * @throws IOException if an exception occurs
	 */
	public SignatureFieldDimensionAndPosition buildSignatureFieldBox() throws IOException {
		if (dimensionAndPosition == null) {
			PDPage originalPage = document
					.getPage(parameters.getFieldParameters().getPage() - ImageUtils.DEFAULT_FIRST_PAGE);
			PDRectangle mediaBox = originalPage.getMediaBox();
			AnnotationBox pageBox = new AnnotationBox(mediaBox.getLowerLeftX(), mediaBox.getLowerLeftY(),
					mediaBox.getUpperRightX(), mediaBox.getUpperRightY());
			SignatureFieldDimensionAndPositionBuilder builder = new SignatureFieldDimensionAndPositionBuilder(
					parameters, getDSSFontMetrics(), pageBox, originalPage.getRotation());
			dimensionAndPosition = builder.build();
		}
		return dimensionAndPosition;
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
	 * @param image {@link DSSDocument} image
	 * @throws IOException in case of image reading error
	 */
	protected void checkColorSpace(PDDocument pdDocument, DSSDocument image) throws IOException {
		if (image != null) {
	        PDDocumentCatalog catalog = pdDocument.getDocumentCatalog();
	        List<PDOutputIntent> profiles = catalog.getOutputIntents();
	        if (Utils.isCollectionEmpty(profiles)) {
	        	LOG.warn("No color profile is present in the document. Not compatible with PDF/A");
	        	return;
	        }
				
			String colorSpaceName = getColorSpaceName(image);
    		if (COSName.DEVICECMYK.getName().equals(colorSpaceName) && isProfilePresent(profiles, RGB_PROFILE_NAME)) {
    			LOG.warn("A CMYK image will be added to an RGB color space PDF. Be aware: not compatible with PDF/A.");
    		} else if (COSName.DEVICERGB.getName().equals(colorSpaceName) && isProfilePresent(profiles, CMYK_PROFILE_NAME)) {
    			LOG.warn("An RGB image will be added to a CMYK color space PDF. Be aware: not compatible with PDF/A.");
    		}
		}
	}
	
	/**
	 * Returns color space name for the provided image
	 * 
	 * @param image {@link DSSDocument} to get color space name for
	 * @return {@link String} color space name
	 * @throws IOException in case of image reading error
	 */
	protected abstract String getColorSpaceName(DSSDocument image) throws IOException;
	
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

}
