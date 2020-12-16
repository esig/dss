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

import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.visible.SignatureFieldBoxBuilder;

import java.io.IOException;

/**
 * The abstract implementation of an IText (OpenPDF) signature drawer
 */
public abstract class AbstractITextSignatureDrawer implements ITextSignatureDrawer, SignatureFieldBoxBuilder {

	/** The signature field id to be signed */
	protected String signatureFieldId;

	/** Visual signature parameters */
	protected SignatureImageParameters parameters;

	/** The visual signature appearance */
	protected PdfSignatureAppearance appearance;

	@Override
	public void init(String signatureFieldId, SignatureImageParameters parameters, PdfSignatureAppearance appearance) throws IOException {
		this.signatureFieldId = signatureFieldId;
		this.parameters = parameters;
		this.appearance = appearance;
	}
	
	/**
	 * Transforms the given {@code appearanceRectangle} to a {@code com.lowagie.text.Rectangle}
	 * with the given page size
	 * 
	 * @param appearanceRectangle {@link ITextVisualSignatureAppearance}
	 * @return {@link com.lowagie.text.Rectangle}
	 */
	protected Rectangle toITextRectangle(ITextVisualSignatureAppearance appearanceRectangle) {
		Rectangle pageRectangle = appearance.getStamper().getReader().getPageSize(parameters.getFieldParameters().getPage());
		float pageHeight = pageRectangle.getHeight();
		
		AnnotationBox annotationBox = appearanceRectangle.getAnnotationBox();
		annotationBox = annotationBox.toPdfPageCoordinates(pageHeight);
		
		return new Rectangle(annotationBox.getMinX(), annotationBox.getMinY(), annotationBox.getMaxX(), annotationBox.getMaxY());
	}

}
