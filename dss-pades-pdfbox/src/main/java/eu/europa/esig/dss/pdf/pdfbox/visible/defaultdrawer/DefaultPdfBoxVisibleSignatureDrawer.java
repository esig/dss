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
package eu.europa.esig.dss.pdf.pdfbox.visible.defaultdrawer;

import eu.europa.esig.dss.pades.DSSFont;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.pdfbox.visible.AbstractPdfBoxSignatureDrawer;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.pdf.visible.SignatureFieldDimensionAndPosition;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDPage;
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

	/**
	 * Default constructor
	 */
	public DefaultPdfBoxVisibleSignatureDrawer() {
		// empty
	}

	@Override
	protected JavaDSSFontMetrics getDSSFontMetrics() {
		SignatureImageTextParameters textParameters = parameters.getTextParameters();
		DSSFont dssFont = textParameters.getFont();

		Font javaFont = dssFont.getJavaFont();
		float properSize = dssFont.getSize() * ImageUtils.getScaleFactor(parameters.getZoom()); // scale text block
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
			textImage = DefaultImageDrawerUtils.createTextImage(parameters, dimensionAndPosition, getDSSFontMetrics());
		}
		if (image == null && textImage == null) {
			throw new IllegalArgumentException("Image or text shall be defined in order to build a visual signature!");
		}

		BufferedImage bufferedImage = DefaultImageDrawerUtils.mergeImages(image, textImage, dimensionAndPosition, parameters);
		bufferedImage = DefaultImageDrawerUtils.rotate(bufferedImage, dimensionAndPosition.getGlobalRotation());

		int page = parameters.getFieldParameters().getPage();
		PDVisibleSignDesigner visibleSig = new PDVisibleSignDesigner(document, bufferedImage, page);

		PDPage originalPage = getPage();
		AnnotationBox pageBox = getPageAnnotationBox(originalPage);

		AnnotationBox annotationBox = dimensionAndPosition.getAnnotationBox();
		visibleSig.xAxis(annotationBox.getMinX());
		visibleSig.yAxis(pageBox.getHeight() - annotationBox.getMaxY()); // PdfBox Default requires coordinates from the upper left corner
		visibleSig.width(annotationBox.getWidth());
		visibleSig.height(annotationBox.getHeight());

		PDVisibleSigProperties signatureProperties = new PDVisibleSigProperties();
		signatureProperties.visualSignEnabled(true);
		signatureProperties.setPdVisibleSignature(visibleSig);
		signatureProperties.buildSignature();

		signatureOptions.setVisualSignature(signatureProperties);
	}

	@Override
	protected String getExpectedColorSpaceName() {
		if (parameters.getImage() != null) {
			// RGB image is being created for Default Drawer
			return COSName.DEVICERGB.getName();
		} else {
			return ImageUtils.containRGBColor(parameters) ? COSName.DEVICERGB.getName() : COSName.DEVICEGRAY.getName();
		}
	}

}
