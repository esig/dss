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
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfTemplate;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.DSSFont;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.pdf.visible.SignatureFieldDimensionAndPosition;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

import java.io.IOException;
import java.io.InputStream;

/**
 * iText drawer used for visual signatures creation with text data only
 *
 */
public class TextOnlySignatureDrawer extends AbstractITextSignatureDrawer {
	
	/**
	 * Initialized font
	 *
	 */
	private Font iTextFont;
	
	@Override
	public void init(SignatureImageParameters parameters, PdfReader reader, PdfSignatureAppearance appearance) {
		super.init(parameters, reader, appearance);
		this.iTextFont = initFont();
	}

	@Override
	public void draw() {
		String text = parameters.getTextParameters().getText();
		appearance.setRender(PdfSignatureAppearance.SignatureRenderDescription);

		String signatureFieldId = parameters.getFieldParameters().getFieldId();
		if (Utils.isStringNotBlank(signatureFieldId)) {
			appearance.setVisibleSignature(signatureFieldId);

			appearance.setLayer2Font(iTextFont);
			appearance.setLayer2Text(text);
			
		} else {
			SignatureFieldDimensionAndPosition dimensionAndPosition = buildSignatureFieldBox();
			Rectangle iTextRectangle = toITextRectangle(dimensionAndPosition);
			appearance.setVisibleSignature(iTextRectangle, parameters.getFieldParameters().getPage()); // defines signature field borders
			drawText(dimensionAndPosition, iTextRectangle);
		}

	}

	private Font initFont() {
		SignatureImageTextParameters textParameters = parameters.getTextParameters();
		DSSFont dssFont = textParameters.getFont();
		BaseFont baseFont = getBaseFont(dssFont);
		Font font = new Font(baseFont, dssFont.getSize());
		font.setColor(textParameters.getTextColor());
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
				baseFont.setSubset(false);
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
	
	private void drawText(SignatureFieldDimensionAndPosition dimensionAndPosition, Rectangle sigFieldRect) {

		ITextDSSFontMetrics iTextFontMetrics = getDSSFontMetrics();
		SignatureImageTextParameters textParameters = parameters.getTextParameters();
		String text = textParameters.getText();

		float size = getProperSize();
		
		PdfTemplate layer = appearance.getLayer(2);
		layer.setFontAndSize(iTextFont.getBaseFont(), size);
		
		Rectangle boundingRectangle = new Rectangle(sigFieldRect.getWidth(), sigFieldRect.getHeight()); // defines text field borders
		boundingRectangle.setBackgroundColor(textParameters.getBackgroundColor());
		layer.rectangle(boundingRectangle);
		
		layer.setBoundingBox(boundingRectangle);
		layer.setColorFill(textParameters.getTextColor());
		
		String[] lines = iTextFontMetrics.getLines(text);
		
		layer.beginText();
		
		// compute initial position
		float x = dimensionAndPosition.getTextX();
		float y = dimensionAndPosition.getTextY() + dimensionAndPosition.getTextHeight()
				- iTextFontMetrics.getDescentPoint(lines[0], size);
		
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
					offsetX = boundingRectangle.getWidth() - lineWidth - textParameters.getPadding() * 2 - previousOffset;
					break;
				case CENTER:
					offsetX = (boundingRectangle.getWidth() - lineWidth) / 2 - textParameters.getPadding() - previousOffset;
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

	private float getProperSize() {
		float size = parameters.getTextParameters().getFont().getSize();
		size *= ImageUtils.getScaleFactor(parameters.getZoom()); // scale text block
		return size;
	}

}
