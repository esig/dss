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

import java.awt.Dimension;
import java.io.IOException;

import com.lowagie.text.Font;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.PdfSignatureAppearance;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.visible.FontUtils;
import eu.europa.esig.dss.utils.Utils;

public class TextOnlySignatureDrawer extends AbstractITextSignatureDrawer {
	
	private Font iTextFont;
	
	@Override
	public void init(String signatureFieldId, SignatureImageParameters parameters, PdfSignatureAppearance appearance) throws IOException {
		super.init(signatureFieldId, parameters, appearance);
		this.iTextFont = initFont();
	}

	@Override
	public void draw() {

		String text = parameters.getTextParameters().getText();
		

		if (Utils.isStringNotBlank(signatureFieldId)) {
			appearance.setVisibleSignature(signatureFieldId);
		} else {
			Rectangle pageSize = appearance.getStamper().getReader().getPageSize(parameters.getPage());
			float originY = pageSize.getHeight();

			int width = parameters.getWidth();
			int height = parameters.getHeight();
			if (width == 0 || height == 0) {
				SignatureImageTextParameters textParameters = parameters.getTextParameters();
				Dimension dimension = FontUtils.computeSize(textParameters.getJavaFont(), text, textParameters.getMargin());
				width = dimension.width;
				height = dimension.height;
			}

			Rectangle rect = new Rectangle(parameters.getxAxis(), originY - parameters.getyAxis() - height, parameters.getxAxis() + width,
					originY - parameters.getyAxis());
			rect.setBackgroundColor(parameters.getBackgroundColor());
			appearance.setVisibleSignature(rect, parameters.getPage());

		}

		appearance.setRender(PdfSignatureAppearance.SignatureRenderDescription);
		appearance.setLayer2Font(iTextFont);
		appearance.setLayer2Text(text);

	}

	private Font initFont() throws IOException {
		try {
			SignatureImageTextParameters textParameters = parameters.getTextParameters();
			DSSDocument dssFont = textParameters.getFont();
			byte[] fontBytes = DSSUtils.toByteArray(dssFont);
			BaseFont baseFont = BaseFont.createFont(dssFont.getName(), BaseFont.WINANSI, BaseFont.EMBEDDED, true, fontBytes, null);
			baseFont.setSubset(false);
			Font font = new Font(baseFont, textParameters.getSize());
			font.setColor(textParameters.getTextColor());
			return font;
		} catch (IOException e) {
			throw new IOException("The iText font cannot be initialized", e);
		}
	}

}
