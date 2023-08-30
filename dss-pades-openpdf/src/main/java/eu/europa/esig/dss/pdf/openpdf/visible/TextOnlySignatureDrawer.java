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
package eu.europa.esig.dss.pdf.openpdf.visible;

import com.lowagie.text.Font;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.DefaultFontMapper;
import com.lowagie.text.pdf.ExtendedColor;
import com.lowagie.text.pdf.GrayColor;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfTemplate;
import com.lowagie.text.pdf.RGBColor;
import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.DSSFont;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.encryption.DSSSecureRandomProvider;
import eu.europa.esig.dss.pdf.visible.ImageRotationUtils;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.pdf.visible.SignatureFieldDimensionAndPosition;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

import java.awt.Color;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

/**
 * iText drawer used for visual signature creation with text data only
 *
 */
public class TextOnlySignatureDrawer extends AbstractITextSignatureDrawer {
	
	/**
	 * Initialized font
	 *
	 */
	private Font iTextFont;

	/**
	 * Default constructor with null font
	 */
	public TextOnlySignatureDrawer() {
		// empty
	}
	
	@Override
	public void init(SignatureImageParameters parameters, PdfReader reader, PdfSignatureAppearance appearance) {
		super.init(parameters, reader, appearance);
		this.iTextFont = initFont();
	}

	@Override
	public void draw() {
		appearance.setRender(PdfSignatureAppearance.SignatureRenderDescription);
		SignatureFieldDimensionAndPosition dimensionAndPosition = buildSignatureFieldBox();

		String signatureFieldId = parameters.getFieldParameters().getFieldId();
		if (Utils.isStringNotBlank(signatureFieldId)) {
			appearance.setVisibleSignature(signatureFieldId);
		} else {
			AnnotationBox annotationBox = toAnnotationBox(dimensionAndPosition);
			annotationBox = getRotatedAnnotationRelativelyPageRotation(annotationBox);
			appearance.setVisibleSignature(toITextRectangle(annotationBox), parameters.getFieldParameters().getPage()); // defines signature field borders
		}

		drawText(dimensionAndPosition);
	}

	private Font initFont() {
		SignatureImageTextParameters textParameters = parameters.getTextParameters();
		DSSFont dssFont = textParameters.getFont();
		BaseFont baseFont = getBaseFont(dssFont);
		Font font = new Font(baseFont, dssFont.getSize());
		font.setColor(toExtendedColor(textParameters.getTextColor()));
		return font;
	}
	
	private BaseFont getBaseFont(DSSFont dssFont) {
		if (dssFont instanceof ITextNativeFont) {
			ITextNativeFont nativeFont = (ITextNativeFont) dssFont;
			return nativeFont.getFont();

		} else if (dssFont instanceof DSSFileFont) {
			DSSFileFont fileFont = (DSSFileFont) dssFont;
			try (InputStream iStream = fileFont.getInputStream()) {
				byte[] fontBytes = DSSUtils.toByteArray(iStream);
				BaseFont baseFont = BaseFont.createFont(fileFont.getName(), BaseFont.IDENTITY_H, BaseFont.EMBEDDED, true, fontBytes, null);
				baseFont.setSubset(fileFont.isEmbedFontSubset());

				// Provide SecureRandom to ensure deterministic computation
				SecureRandom secureRandom = new DSSSecureRandomProvider(parameters).getSecureRandom();
				baseFont.setSecureRandom(secureRandom);

				return baseFont;

			} catch (IOException e) {
				throw new DSSException("The iText font cannot be initialized", e);
			}

		} else {
			DefaultFontMapper fontMapper = new DefaultFontMapper();
			return fontMapper.awtToPdf(dssFont.getJavaFont());
		}
	}

	@Override
	protected ITextDSSFontMetrics getDSSFontMetrics() {
		return new ITextDSSFontMetrics(iTextFont.getBaseFont());
	}
	
	@Override
	protected PdfName getExpectedColorSpaceName() {
		return ImageUtils.containRGBColor(parameters) ? PdfName.DEVICERGB : PdfName.DEVICEGRAY;
	}

	private void drawText(SignatureFieldDimensionAndPosition dimensionAndPosition) {

		ITextDSSFontMetrics iTextFontMetrics = getDSSFontMetrics();
		SignatureImageTextParameters textParameters = parameters.getTextParameters();
		String text = dimensionAndPosition.getText();

		float size = dimensionAndPosition.getTextSize();
		
		PdfTemplate layer = appearance.getLayer(2);
		layer.setFontAndSize(iTextFont.getBaseFont(), size);

		Rectangle textRectangle = getTextBoxRectangle(dimensionAndPosition);
		textRectangle.setBackgroundColor(toExtendedColor(textParameters.getBackgroundColor()));
		layer.rectangle(textRectangle);

		if (textParameters.getTextColor() != null) {
			layer.setColorFill(toExtendedColor(textParameters.getTextColor()));
		}
		
		String[] lines = iTextFontMetrics.getLines(text);
		
		layer.beginText();

		rotateText(layer, dimensionAndPosition.getBoxWidth(), dimensionAndPosition.getBoxHeight(),
				dimensionAndPosition.getGlobalRotation());
		
		// compute initial position
		float x = dimensionAndPosition.getTextX();
		float y = dimensionAndPosition.getTextY() + dimensionAndPosition.getTextHeight() -
				iTextFontMetrics.getDescentPoint(lines[0], size);
		
		layer.moveText(x, y);
		layer.newlineText();
		
		float strHeight = iTextFontMetrics.getHeight(lines[0], size);
		y = -strHeight;

        float previousOffset = 0;
		for (String line : lines) {
            float offsetX = 0;
			float lineWidth = iTextFontMetrics.getWidth(line, size);
			switch (textParameters.getSignerTextHorizontalAlignment()) {
				case RIGHT:
					offsetX = dimensionAndPosition.getTextBoxWidth() - lineWidth - textParameters.getPadding() * 2 - previousOffset;
					break;
				case CENTER:
					offsetX = (dimensionAndPosition.getTextBoxWidth() - lineWidth) / 2 - textParameters.getPadding() - previousOffset;
					break;
				default:
					break;
			}
			previousOffset += offsetX;
			layer.moveText(offsetX, y);
			layer.newlineShowText(line);
		}
		
		layer.endText();
	}

	private ExtendedColor toExtendedColor(Color color) {
		if (color == null) {
			return null;
		}
		if (ImageUtils.isGrayscale(color)) {
			return new GrayColor(color.getRed());
		} else {
			return new RGBColor(color.getRed(), color.getGreen(), color.getBlue(), color.getAlpha());
		}
	}

	private Rectangle getTextBoxRectangle(SignatureFieldDimensionAndPosition dimensionAndPosition) {
		AnnotationBox signatureFieldAnnotationBox = toAnnotationBox(dimensionAndPosition);
		// Main field is returned pre-rotated
		VisualSignatureRotation rotation = parameters.getFieldParameters().getRotation();
		if (ImageRotationUtils.isSwapOfDimensionsRequired(rotation)) {
			signatureFieldAnnotationBox = ImageRotationUtils.swapDimensions(signatureFieldAnnotationBox);
		}
		AnnotationBox textBox = new AnnotationBox(dimensionAndPosition.getTextBoxX(), dimensionAndPosition.getTextBoxY(),
				dimensionAndPosition.getTextBoxWidth() + dimensionAndPosition.getTextBoxX(),
				dimensionAndPosition.getTextBoxHeight() + dimensionAndPosition.getTextBoxY());
		int finalRotation = getFinalRotation(dimensionAndPosition.getGlobalRotation(), getPageRotation());
		textBox = ImageRotationUtils.rotateRelativelyWrappingBox(textBox, signatureFieldAnnotationBox, finalRotation);
		return toITextRectangle(textBox);
	}

	private void rotateText(PdfTemplate layer, float width, float height, int globalRotation) {
		int pageRotation = getPageRotation();
		if (ImageRotationUtils.isSwapOfDimensionsRequired(pageRotation)) {
			float temp = height;
			height = width;
			width = temp;
		}
		// OpenPDF does not rotate signature automatically to the page's rotation
		int finalRotation = getFinalRotation(globalRotation, pageRotation);
		double theta = Math.toRadians((double) ImageRotationUtils.ANGLE_360 - finalRotation);
		float cosTheta = (float)Math.cos(theta);
		float sinTheta = (float)Math.sin(theta);
		switch (finalRotation) {
			case ImageRotationUtils.ANGLE_90:
				layer.setTextMatrix(cosTheta, sinTheta, -sinTheta, cosTheta, 0, height);
				break;
			case ImageRotationUtils.ANGLE_180:
				layer.setTextMatrix(cosTheta, sinTheta, -sinTheta, cosTheta, width, height);
				break;
			case ImageRotationUtils.ANGLE_270:
				layer.setTextMatrix(cosTheta, sinTheta, -sinTheta, cosTheta, width, 0);
				break;
			case ImageRotationUtils.ANGLE_0:
			case ImageRotationUtils.ANGLE_360:
				// do nothing
				break;
			default:
				throw new IllegalStateException(ImageRotationUtils.SUPPORTED_ANGLES_ERROR_MESSAGE);
		}
	}

}
