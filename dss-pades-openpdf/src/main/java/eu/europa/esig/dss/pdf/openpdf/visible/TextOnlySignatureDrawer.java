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

import com.lowagie.text.Font;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.PdfSignatureAppearance;

import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.visible.ImageTextWriter;
import eu.europa.esig.dss.utils.Utils;

public class TextOnlySignatureDrawer extends AbstractITextSignatureDrawer {

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
				Dimension dimension = ImageTextWriter.computeSize(parameters.getTextParameters().getFont(), text);
				width = dimension.width;
				height = dimension.height;
			}

			Rectangle rect = new Rectangle(parameters.getxAxis(), originY - parameters.getyAxis() - height, parameters.getxAxis() + width,
					originY - parameters.getyAxis());
			rect.setBackgroundColor(parameters.getBackgroundColor());
			appearance.setVisibleSignature(rect, parameters.getPage());

		}

		appearance.setRender(PdfSignatureAppearance.SignatureRenderDescription);
		appearance.setLayer2Font(getFont());
		appearance.setLayer2Text(text);

	}

	private Font getFont() {
		SignatureImageTextParameters textParameters = parameters.getTextParameters();

		java.awt.Font font = textParameters.getFont();

		Font itextFont = new Font();
		itextFont.setFamily(font.getFamily());
		itextFont.setSize(font.getSize());
		itextFont.setStyle(font.getStyle());

		itextFont.setColor(textParameters.getTextColor());
		return itextFont;
	}

}
