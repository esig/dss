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
package eu.europa.esig.dss.pdf.pdfbox;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;

public class PdfBoxInvisibleSignatureOptionsPreparator {

	public void prepare(SignatureOptions signatureOptions) throws IOException {

		try (PDDocument doc = new PDDocument(); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			
			PDAcroForm acroForm = new PDAcroForm(doc);
			doc.getDocumentCatalog().setAcroForm(acroForm);
			PDSignatureField signatureField = new PDSignatureField(acroForm);
			PDAnnotationWidget widget = signatureField.getWidgets().get(0);
			List<PDField> acroFormFields = acroForm.getFields();
			acroFormFields.add(signatureField);

			PDRectangle rectangle = createEmptyRectangle();
			widget.setRectangle(rectangle);

			PDStream stream = new PDStream(doc);
			PDFormXObject form = new PDFormXObject(stream);

			form.setBBox(rectangle);

			PDAppearanceDictionary appearance = new PDAppearanceDictionary();
			appearance.getCOSObject().setDirect(true);
			PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
			appearance.setNormalAppearance(appearanceStream);
			widget.setAppearance(appearance);

			doc.save(baos);
			
			try (ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray())) {
				signatureOptions.setVisualSignature(bais);
				signatureOptions.setPage(0);
			}

		}
	}

	private PDRectangle createEmptyRectangle() {
		PDRectangle rectangle = new PDRectangle();
		rectangle.setLowerLeftX(0);
		rectangle.setLowerLeftY(0);
		rectangle.setUpperRightX(0);
		rectangle.setUpperRightY(0);
		return rectangle;
	}

}
