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
package eu.europa.esig.dss.pades.signature.visible.defaultdrawer;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;
import eu.europa.esig.dss.pdfa.signature.visible.suite.PDFAVisibleSignatureTest;
import org.junit.jupiter.api.Test;

import java.io.IOException;

class DefaultPDFAVisibleSignatureTest extends PDFAVisibleSignatureTest {

	@Override
	protected void setCustomFactory() {
		service.setPdfObjFactory(new PdfBoxDefaultObjectFactory());
	}

	@Test
	void testAddCMYKImageToRGBDoc() throws IOException {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/pdfa2a-rgb.pdf"));

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/cmyk.jpg"), "cmyk.jpg", MimeTypeEnum.JPEG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);

		signatureParameters.setImageParameters(imageParameters);

		// an RGB image is created
		signAndValidate("PDF/A-2A", true);
	}

	@Test
	void testAddGrayscalePNGImageToGrayColorSpaceDoc() throws IOException {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/pdfa2a-gray.pdf"));

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		// iText does not support PNG-grayscale images
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/grayscale_image.png"), "grayscale_image.png", MimeTypeEnum.PNG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		fieldParameters.setWidth(100);
		fieldParameters.setHeight(150);
		imageParameters.setFieldParameters(fieldParameters);

		signatureParameters.setImageParameters(imageParameters);

		signAndValidate("PDF/A-2A", true);
	}

}
