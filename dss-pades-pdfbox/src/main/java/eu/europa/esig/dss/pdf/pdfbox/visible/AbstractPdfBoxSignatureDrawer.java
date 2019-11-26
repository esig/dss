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

import java.io.IOException;
import java.util.List;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.graphics.color.PDOutputIntent;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.utils.Utils;

public abstract class AbstractPdfBoxSignatureDrawer implements PdfBoxSignatureDrawer {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractPdfBoxSignatureDrawer.class);

	private static final String CMYK_PROFILE_NAME = "cmyk";
	private static final String RGB_PROFILE_NAME = "rgb";

	protected SignatureImageParameters parameters;
	protected PDDocument document;
	protected SignatureOptions signatureOptions;

	@Override
	public void init(SignatureImageParameters parameters, PDDocument document, SignatureOptions signatureOptions) throws IOException {
		assertSignatureParamatersAreValid(parameters);
		this.parameters = parameters;
		this.document = document;
		this.signatureOptions = signatureOptions;
		checkColorSpace(document, parameters.getImage());
	}
	
	private void assertSignatureParamatersAreValid(SignatureImageParameters parameters) {
		if (parameters == null || parameters.getImage() == null && parameters.getTextParameters() == null) {
			throw new DSSException("Neither image nor text parameters are defined!");
		}
	}
	
	/**
	 * Method to check if the target image's colro space is present in the document's catalog
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
