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
import java.io.InputStream;

import com.lowagie.text.Font;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.DefaultFontMapper;
import com.lowagie.text.pdf.PdfSignatureAppearance;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.pades.DSSFont;
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
				Dimension dimension = FontUtils.computeSize(textParameters.getFont(), text, textParameters.getPadding());
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
		SignatureImageTextParameters textParameters = parameters.getTextParameters();
		DSSFont dssFont = textParameters.getFont();
		BaseFont baseFont;
		if (dssFont.isLogicalFont()) {
			DefaultFontMapper fontMapper = new DefaultFontMapper();
			baseFont = fontMapper.awtToPdf(dssFont.getJavaFont());
		} else {
			try (InputStream iStream = dssFont.getInputStream()) {
				byte[] fontBytes = DSSUtils.toByteArray(iStream);
				baseFont = BaseFont.createFont(dssFont.getName(), BaseFont.IDENTITY_H, BaseFont.EMBEDDED, true, fontBytes, null);
				baseFont.setSubset(false);
			} catch (IOException e) {
				throw new DSSException("The iText font cannot be initialized", e);
			}
		}
		Font font = new Font(baseFont, dssFont.getSize());
		font.setColor(textParameters.getTextColor());
		return font;
	}

}
