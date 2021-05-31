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
package eu.europa.esig.dss.pdf.pdfbox.visible.defaultdrawer;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.DSSFont;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.pdfbox.visible.AbstractPdfBoxSignatureDrawer;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.pdf.visible.SignatureFieldDimensionAndPosition;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;

import java.awt.Font;
import java.awt.image.BufferedImage;
import java.io.IOException;

/**
 * The default PDFBox signature drawer.
 * Creates an image for a text content of the signature.
 */
public class DefaultPdfBoxVisibleSignatureDrawer extends AbstractPdfBoxSignatureDrawer {

	@Override
	protected JavaDSSFontMetrics getDSSFontMetrics() {
		SignatureImageTextParameters textParameters = parameters.getTextParameters();
		DSSFont dssFont = textParameters.getFont();

		Font javaFont = dssFont.getJavaFont();
		float properSize = dssFont.getSize()
				* ImageUtils.getScaleFactor(parameters.getZoom()); // scale text block
		Font properFont = javaFont.deriveFont(properSize);

		return new JavaDSSFontMetrics(properFont);
	}

	@Override
	public void draw() throws IOException {
		SignatureFieldDimensionAndPosition dimensionAndPosition = buildSignatureFieldBox();
		BufferedImage image = null;
		BufferedImage textImage = null;
		if (parameters.getImage() != null) {
			image = DefaultImageDrawerUtils.toBufferedImage(parameters.getImage());
		}
		if (parameters.getTextParameters() != null && !parameters.getTextParameters().isEmpty()) {
			textImage = DefaultImageDrawerUtils.createTextImage(parameters, dimensionAndPosition);
		}
		if (image == null && textImage == null) {
			throw new DSSException("Image or text shall be defined in order to build a visual signature!");
		}

		BufferedImage bufferedImage = DefaultImageDrawerUtils.mergeImages(image, textImage, dimensionAndPosition, parameters);
		bufferedImage = DefaultImageDrawerUtils.rotate(bufferedImage, dimensionAndPosition.getGlobalRotation());

		int page = parameters.getFieldParameters().getPage();
		PDVisibleSignDesigner visibleSig = new PDVisibleSignDesigner(document, bufferedImage, page);

		visibleSig.xAxis(dimensionAndPosition.getBoxX());
		visibleSig.yAxis(dimensionAndPosition.getBoxY());
		visibleSig.width(dimensionAndPosition.getBoxWidth());
		visibleSig.height(dimensionAndPosition.getBoxHeight());

		PDVisibleSigProperties signatureProperties = new PDVisibleSigProperties();
		signatureProperties.visualSignEnabled(true);
		signatureProperties.setPdVisibleSignature(visibleSig);
		signatureProperties.buildSignature();

		signatureOptions.setVisualSignature(signatureProperties);
		signatureOptions.setPage(page - ImageUtils.DEFAULT_FIRST_PAGE); // DSS-1138
	}

	@Override
	protected String getColorSpaceName(DSSDocument image) throws IOException {
		return COSName.DEVICERGB.getName();
	}

}
