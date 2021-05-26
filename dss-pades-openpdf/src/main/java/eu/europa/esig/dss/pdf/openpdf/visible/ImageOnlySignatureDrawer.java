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

import com.lowagie.text.Image;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.ColumnText;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfTemplate;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pdf.visible.DSSFontMetrics;
import eu.europa.esig.dss.pdf.visible.SignatureFieldDimensionAndPosition;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

import java.io.IOException;

/**
 * iText drawer used for image only visible signature creation
 *
 */
public class ImageOnlySignatureDrawer extends AbstractITextSignatureDrawer {

	@Override
	public void draw() {
		Image image = getImage();

		SignatureFieldParameters fieldParameters = parameters.getFieldParameters();
		String signatureFieldId = fieldParameters.getFieldId();
		float width = fieldParameters.getWidth();
		float height = fieldParameters.getHeight();

		if (Utils.isStringNotBlank(signatureFieldId)) {
			appearance.setVisibleSignature(signatureFieldId);
			Rectangle rect = appearance.getRect();
			if (rect != null) {
				width = (int) rect.getWidth();
				height = (int) rect.getHeight();
			}
		} else {
			SignatureFieldDimensionAndPosition dimensionAndPosition = buildSignatureFieldBox();
			Rectangle iTextRectangle = toITextRectangle(dimensionAndPosition);
			iTextRectangle.setBackgroundColor(parameters.getBackgroundColor());
			
			width = iTextRectangle.getWidth();
			height = iTextRectangle.getHeight();
			
			appearance.setVisibleSignature(iTextRectangle, fieldParameters.getPage());
		}
		
		image.scaleAbsolute(width, height);

		PdfTemplate layer = appearance.getLayer(2);
		ColumnText ct = new ColumnText(layer);
		ct.setSimpleColumn(0, 0, width, height);
		
		PdfPTable table = new PdfPTable(1);
		table.setWidthPercentage(100);
		PdfPCell pdfPCell = new PdfPCell(image);
		pdfPCell.setBorder(Rectangle.NO_BORDER);
		table.addCell(pdfPCell);
		
		ct.addElement(table);
		ct.go();
	}

	private Image getImage() {
		try {
			return Image.getInstance(DSSUtils.toByteArray(parameters.getImage()));
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to read the provided image file. Reason : %s", e.getMessage()), e);
		}
	}

	@Override
	protected DSSFontMetrics getDSSFontMetrics() {
		// not applicable
		return null;
	}

}
