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
import eu.europa.esig.dss.pdf.visible.SignatureFieldDimensionAndPosition;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

import java.io.IOException;
import java.io.InputStream;

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
			Rectangle iTextRectangle = toITextRectangle(dimensionAndPosition);
			appearance.setVisibleSignature(iTextRectangle, parameters.getFieldParameters().getPage()); // defines signature field borders
		}

		drawText(dimensionAndPosition);
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
				// TODO : add support of subset
				/*
				 * NOTE: OpenPDF does not support yet the deterministic PDF generation when subsets are used
				 * see https://github.com/LibrePDF/OpenPDF/issues/623
				 */
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
	
	private void drawText(SignatureFieldDimensionAndPosition dimensionAndPosition) {

		ITextDSSFontMetrics iTextFontMetrics = getDSSFontMetrics();
		SignatureImageTextParameters textParameters = parameters.getTextParameters();
		String text = dimensionAndPosition.getText();

		float size = dimensionAndPosition.getTextSize();
		
		PdfTemplate layer = appearance.getLayer(2);
		layer.setFontAndSize(iTextFont.getBaseFont(), size);

		Rectangle textRectangle = new Rectangle(dimensionAndPosition.getTextBoxX(), dimensionAndPosition.getTextBoxY(),
				dimensionAndPosition.getTextBoxWidth() + dimensionAndPosition.getTextBoxX(),
				dimensionAndPosition.getTextBoxHeight() + dimensionAndPosition.getTextBoxY());
		textRectangle.setBackgroundColor(textParameters.getBackgroundColor());
		layer.rectangle(textRectangle);

		if (textParameters.getTextColor() != null) {
			layer.setColorFill(textParameters.getTextColor());
		}
		
		String[] lines = iTextFontMetrics.getLines(text);
		
		layer.beginText();
		
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

}
