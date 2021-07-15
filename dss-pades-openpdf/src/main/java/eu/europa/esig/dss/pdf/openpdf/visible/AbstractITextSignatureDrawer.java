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
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.visible.DSSFontMetrics;
import eu.europa.esig.dss.pdf.visible.SignatureFieldBoxBuilder;
import eu.europa.esig.dss.pdf.visible.SignatureFieldDimensionAndPosition;
import eu.europa.esig.dss.pdf.visible.SignatureFieldDimensionAndPositionBuilder;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * The abstract implementation of an IText (OpenPDF) signature drawer
 */
public abstract class AbstractITextSignatureDrawer implements ITextSignatureDrawer, SignatureFieldBoxBuilder {

	/** PdfReader */
	private PdfReader reader;

	/** Visual signature parameters */
	protected SignatureImageParameters parameters;

	/** The visual signature appearance */
	protected PdfSignatureAppearance appearance;

	@Override
	public void init(SignatureImageParameters parameters, PdfReader reader, PdfSignatureAppearance appearance) {
		this.parameters = parameters;
		this.reader = reader;
		this.appearance = appearance;
	}
	
	/**
	 * Builds a signature field dimension and position object
	 *
	 * @return {@link SignatureFieldDimensionAndPosition}
	 */
	public SignatureFieldDimensionAndPosition buildSignatureFieldBox() {
		AnnotationBox pageBox = getPageAnnotationBox();
		int pageRotation = reader.getPageRotation(parameters.getFieldParameters().getPage());
		return new SignatureFieldDimensionAndPositionBuilder(parameters, getDSSFontMetrics(), pageBox, pageRotation)
				.setSignatureFieldAnnotationBox(getSignatureFieldAnnotationBox()).build();
	}

	/**
	 * Returns the associated with the drawer font metrics
	 *
	 * @return {@link DSSFontMetrics}
	 */
	protected abstract DSSFontMetrics getDSSFontMetrics();

	/**
	 * Returns the page's box
	 *
	 * @return {@link AnnotationBox}
	 */
	protected AnnotationBox getPageAnnotationBox() {
		int pageNumber = parameters.getFieldParameters().getPage();
		Rectangle rectangle = reader.getPageSize(pageNumber);
		return new AnnotationBox(0, 0, rectangle.getWidth(), rectangle.getHeight());
	}

	/**
	 * Transforms the given {@code dimensionAndPosition} to a {@code com.lowagie.text.Rectangle}
	 * with the given page size
	 *
	 * @param dimensionAndPosition {@link SignatureFieldDimensionAndPosition}
	 * @return {@link com.lowagie.text.Rectangle}
	 */
	protected Rectangle toITextRectangle(SignatureFieldDimensionAndPosition dimensionAndPosition) {
		AnnotationBox pageBox = getPageAnnotationBox();
		return new Rectangle(dimensionAndPosition.getBoxX(),
				pageBox.getHeight() - dimensionAndPosition.getBoxY() - dimensionAndPosition.getBoxHeight(),
				dimensionAndPosition.getBoxX() + dimensionAndPosition.getBoxWidth(),
				pageBox.getHeight() - dimensionAndPosition.getBoxY(),
				dimensionAndPosition.getGlobalRotation());
	}

	private AnnotationBox getSignatureFieldAnnotationBox() {
		AcroFields.Item signatureField = getExistingSignatureFieldToFill();
		if (signatureField != null) {
			PdfDictionary widget = signatureField.getWidget(0);
			if (widget != null) {
				PdfArray rectArray = widget.getAsArray(PdfName.RECT);
				if (rectArray != null && rectArray.size() == 4) {
					return new AnnotationBox(rectArray.getAsNumber(0).floatValue(), rectArray.getAsNumber(1).floatValue(),
							rectArray.getAsNumber(2).floatValue(), rectArray.getAsNumber(3).floatValue());
				}
			}
		}
		return null;
	}

	private AcroFields.Item getExistingSignatureFieldToFill() {
		String signatureFieldId = parameters.getFieldParameters().getFieldId();
		if (Utils.isStringNotEmpty(signatureFieldId)) {
			AcroFields acroFields = reader.getAcroFields();
			List<String> signatureNames = acroFields.getFieldNamesWithBlankSignatures();
			if (signatureNames.contains(signatureFieldId)) {
				return acroFields.getFieldItem(signatureFieldId);
			}
		}
		return null;
	}

}
