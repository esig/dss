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
package eu.europa.esig.dss.pades.signature.visible.suite;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pdf.AbstractPDFSignatureService;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PdfPermissionsChecker;
import eu.europa.esig.dss.pdf.PdfSignatureFieldPositionChecker;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PDFSignatureServiceTest {
	
	private AbstractPDFSignatureService service;
	
	@BeforeEach
	public void init() {
		IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();
		service = (AbstractPDFSignatureService) pdfObjFactory.newPAdESSignatureService();
	}
	
	@Test
	public void alertOnSignatureFieldOverlapTest() throws IOException {
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/EmptyPage.pdf"));
		
		SignatureFieldParameters parametersOne = new SignatureFieldParameters();
		parametersOne.setFieldId("signature1");
		parametersOne.setOriginX(0);
		parametersOne.setOriginY(0);
		parametersOne.setHeight(100);
		parametersOne.setWidth(100);
		DSSDocument withFirstField = service.addNewSignatureField(documentToSign, parametersOne);
		assertNotNull(withFirstField);
		
		SignatureFieldParameters parametersTwo = new SignatureFieldParameters();
		parametersTwo.setOriginX(25);
		parametersTwo.setOriginY(25);
		parametersTwo.setHeight(100);
		parametersTwo.setWidth(100);
		parametersTwo.setFieldId("signature2");
		Exception exception = assertThrows(AlertException.class, () -> service.addNewSignatureField(withFirstField, parametersTwo));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		PdfSignatureFieldPositionChecker pdfSignatureFieldPositionChecker = new PdfSignatureFieldPositionChecker();
		pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOverlap(new LogOnStatusAlert());
		service.setPdfSignatureFieldPositionChecker(pdfSignatureFieldPositionChecker);

		DSSDocument withSecondField = service.addNewSignatureField(withFirstField, parametersTwo);
		assertNotNull(withSecondField);
		
		assertEquals(2, service.getAvailableSignatureFields(withSecondField).size());
	}

	@Test
	public void alertOnSignatureFieldOutsidePageDimensions() throws IOException {
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/EmptyPage.pdf"));

		PdfSignatureFieldPositionChecker pdfSignatureFieldPositionChecker = new PdfSignatureFieldPositionChecker();
		pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOutsidePageDimensions(new ExceptionOnStatusAlert());
		service.setPdfSignatureFieldPositionChecker(pdfSignatureFieldPositionChecker);

		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setFieldId("signature1");
		parameters.setOriginX(0);
		parameters.setOriginY(0);
		parameters.setHeight(0);
		parameters.setWidth(0);
		DSSDocument signedDoc = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(signedDoc);

		parameters.setOriginX(0);
		parameters.setOriginY(0);
		parameters.setHeight(100);
		parameters.setWidth(100);
		signedDoc = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(signedDoc);

		parameters.setOriginX(200);
		parameters.setOriginY(200);
		parameters.setHeight(100);
		parameters.setWidth(100);
		signedDoc = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(signedDoc);

		parameters.setOriginX(-1);
		parameters.setOriginY(0);
		parameters.setHeight(100);
		parameters.setWidth(100);
		Exception exception = assertThrows(AlertException.class, () -> service.addNewSignatureField(documentToSign, parameters));
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOutsidePageDimensions(new LogOnStatusAlert());
		signedDoc = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(signedDoc);

		pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOutsidePageDimensions(new ExceptionOnStatusAlert());
		parameters.setOriginX(0);
		parameters.setOriginY(-1);
		parameters.setHeight(100);
		parameters.setWidth(100);
		exception = assertThrows(AlertException.class, () -> service.addNewSignatureField(documentToSign, parameters));
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOutsidePageDimensions(new LogOnStatusAlert());
		signedDoc = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(signedDoc);

		pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOutsidePageDimensions(new ExceptionOnStatusAlert());
		parameters.setOriginX(0);
		parameters.setOriginY(0);
		parameters.setHeight(100);
		parameters.setWidth(100);
		signedDoc = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(signedDoc);

		parameters.setOriginX(612);
		parameters.setOriginY(792);
		parameters.setHeight(0);
		parameters.setWidth(0);
		signedDoc = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(signedDoc);

		parameters.setOriginX(512);
		parameters.setOriginY(692);
		parameters.setHeight(100);
		parameters.setWidth(100);
		signedDoc = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(signedDoc);

		parameters.setOriginX(513);
		parameters.setOriginY(692);
		parameters.setHeight(100);
		parameters.setWidth(100);
		exception = assertThrows(AlertException.class, () -> service.addNewSignatureField(documentToSign, parameters));
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOutsidePageDimensions(new LogOnStatusAlert());
		signedDoc = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(signedDoc);

		pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOutsidePageDimensions(new ExceptionOnStatusAlert());
		parameters.setOriginX(512);
		parameters.setOriginY(692);
		parameters.setHeight(101);
		parameters.setWidth(100);
		exception = assertThrows(AlertException.class, () -> service.addNewSignatureField(documentToSign, parameters));
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOutsidePageDimensions(new LogOnStatusAlert());
		signedDoc = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(signedDoc);

		pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOutsidePageDimensions(new ExceptionOnStatusAlert());
		parameters.setOriginX(512);
		parameters.setOriginY(693);
		parameters.setHeight(100);
		parameters.setWidth(100);
		exception = assertThrows(AlertException.class, () -> service.addNewSignatureField(documentToSign, parameters));
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOutsidePageDimensions(new LogOnStatusAlert());
		signedDoc = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(signedDoc);

		pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOutsidePageDimensions(new ExceptionOnStatusAlert());
		parameters.setOriginX(512);
		parameters.setOriginY(692);
		parameters.setHeight(100);
		parameters.setWidth(101);
		exception = assertThrows(AlertException.class, () -> service.addNewSignatureField(documentToSign, parameters));
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOutsidePageDimensions(new LogOnStatusAlert());
		signedDoc = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(signedDoc);
	}

	@Test
	public void alertOnForbiddenSignatureCreationTest() {
		DSSDocument documentToSign = new InMemoryDocument(
				getClass().getResourceAsStream("/validation/dss-2554/certified-no-change-permitted.pdf"));

		List<String> availableSignatureFields = service.getAvailableSignatureFields(documentToSign);
		assertEquals(0, availableSignatureFields.size());

		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setFieldId("Signature1");

		PdfPermissionsChecker pdfPermissionsChecker = new PdfPermissionsChecker();
		pdfPermissionsChecker.setAlertOnForbiddenSignatureCreation(new ExceptionOnStatusAlert());
		service.setPdfPermissionsChecker(pdfPermissionsChecker);

		Exception exception = assertThrows(AlertException.class, () -> service.addNewSignatureField(documentToSign, parameters));
		assertEquals("The creation of new signatures is not permitted in the current document. " +
				"Reason : DocMDP dictionary does not permit a new signature creation!", exception.getMessage());

		pdfPermissionsChecker.setAlertOnForbiddenSignatureCreation(new SilentOnStatusAlert());
		DSSDocument dssDocumentWithAddedField = service.addNewSignatureField(documentToSign, parameters);

		availableSignatureFields = service.getAvailableSignatureFields(dssDocumentWithAddedField);
		assertEquals(1, availableSignatureFields.size());
		assertEquals("Signature1", availableSignatureFields.get(0));
	}

}
