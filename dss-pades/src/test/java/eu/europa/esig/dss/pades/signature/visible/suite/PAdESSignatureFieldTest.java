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

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.awt.Color;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESSignatureFieldTest extends PKIFactoryAccess {

	private PAdESService service;
	private PAdESSignatureParameters signatureParameters;

	@BeforeEach
	public void init() throws Exception {

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(imageParameters);

		service = new PAdESService(getOfflineCertificateVerifier());
	}

	@Test
	public void testGeneratedTextOnly() throws IOException {

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("Signature1");

		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));
		signAndValidate(documentToSign);
	}

	@Test
	public void testSignTwice() throws IOException {

		// Add second field first
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));

		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setFieldId("test");
		parameters.setOriginX(10);
		parameters.setOriginY(10);
		parameters.setHeight(50);
		parameters.setWidth(50);
		DSSDocument doc = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(doc);

		// Sign twice

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("Signature1");

		DSSDocument doc2 = signAndValidate(doc);
		assertNotNull(doc2);

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("test");

		DSSDocument doc3 = signAndValidate(doc2);
		assertNotNull(doc3);
	}

	@Test
	public void testSignTwoFields() throws IOException {

		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));

		assertEquals(2, countStringOccurrence(documentToSign, "startxref"));
		assertEquals(2, countStringOccurrence(documentToSign, "%%EOF"));

		// add first field
		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setFieldId("signature1");
		parameters.setOriginX(10);
		parameters.setOriginY(10);
		parameters.setHeight(50);
		parameters.setWidth(50);
		DSSDocument withFirstField = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(withFirstField);

		assertEquals(3, countStringOccurrence(withFirstField, "startxref"));
		assertEquals(3, countStringOccurrence(withFirstField, "%%EOF"));

		// add second field
		parameters = new SignatureFieldParameters();
		parameters.setFieldId("signature2");
		parameters.setOriginX(100);
		parameters.setOriginY(10);
		parameters.setHeight(50);
		parameters.setWidth(50);
		DSSDocument secondField = service.addNewSignatureField(withFirstField, parameters);
		assertNotNull(secondField);

		assertEquals(4, countStringOccurrence(secondField, "startxref"));
		assertEquals(4, countStringOccurrence(secondField, "%%EOF"));

		// sign first field
		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
		DSSDocument firstSigned = signAndValidate(secondField);
		assertNotNull(firstSigned);

		assertEquals(5, countStringOccurrence(firstSigned, "startxref"));
		assertEquals(5, countStringOccurrence(firstSigned, "%%EOF"));

		// sign second field
		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature2");
		DSSDocument secondSigned = signAndValidate(firstSigned);
		assertNotNull(secondSigned);

		assertEquals(6, countStringOccurrence(secondSigned, "startxref"));
		assertEquals(6, countStringOccurrence(secondSigned, "%%EOF"));

	}

	@Test
	public void createAndSignConsequently() throws IOException {

		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));

		assertEquals(2, countStringOccurrence(documentToSign, "startxref"));
		assertEquals(2, countStringOccurrence(documentToSign, "%%EOF"));

		// add field and sign
		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setFieldId("signature1");
		parameters.setOriginX(10);
		parameters.setOriginY(10);
		parameters.setHeight(50);
		parameters.setWidth(50);
		DSSDocument withFirstField = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(withFirstField);

		assertEquals(3, countStringOccurrence(withFirstField, "startxref"));
		assertEquals(3, countStringOccurrence(withFirstField, "%%EOF"));

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
		DSSDocument firstSigned = signAndValidate(withFirstField);
		assertNotNull(firstSigned);

		assertEquals(4, countStringOccurrence(firstSigned, "startxref"));
		assertEquals(4, countStringOccurrence(firstSigned, "%%EOF"));

		// add a new field and second sign
		parameters = new SignatureFieldParameters();
		parameters.setFieldId("signature2");
		parameters.setOriginX(100);
		parameters.setOriginY(10);
		parameters.setHeight(50);
		parameters.setWidth(50);
		DSSDocument secondField = service.addNewSignatureField(firstSigned, parameters);
		assertNotNull(secondField);

		assertEquals(5, countStringOccurrence(secondField, "startxref"));
		assertEquals(5, countStringOccurrence(secondField, "%%EOF"));

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature2");
		DSSDocument secondSigned = signAndValidate(secondField);
		assertNotNull(secondSigned);

		assertEquals(6, countStringOccurrence(secondSigned, "startxref"));
		assertEquals(6, countStringOccurrence(secondSigned, "%%EOF"));

	}

	@Test
	public void createFieldInEmptyDocument() throws IOException {

		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/EmptyPage.pdf"));

		assertEquals(2, countStringOccurrence(documentToSign, "startxref"));
		assertEquals(2, countStringOccurrence(documentToSign, "%%EOF"));

		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setFieldId("signature1");
		parameters.setOriginX(10);
		parameters.setOriginY(10);
		parameters.setHeight(50);
		parameters.setWidth(50);
		DSSDocument withFirstField = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(withFirstField);

		assertEquals(3, countStringOccurrence(withFirstField, "startxref"));
		assertEquals(3, countStringOccurrence(withFirstField, "%%EOF"));

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
		DSSDocument firstSigned = signAndValidate(withFirstField);
		assertNotNull(firstSigned);

		assertEquals(4, countStringOccurrence(firstSigned, "startxref"));
		assertEquals(4, countStringOccurrence(firstSigned, "%%EOF"));

	}

	@Test
	public void testSignTwiceSameField() throws IOException {
		signatureParameters.getImageParameters().getFieldParameters().setFieldId("Signature1");

		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));
		DSSDocument doc = signAndValidate(documentToSign);
		assertNotNull(doc);

		assertThrows(IllegalArgumentException.class, () -> signAndValidate(doc));
	}

	@Test
	public void testFieldNotFound() throws IOException {
		signatureParameters.getImageParameters().getFieldParameters().setFieldId("not-found");

		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));
		assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign));
	}

	@Test
	public void fieldsOverlapTest() throws IOException {
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/EmptyPage.pdf"));

		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setFieldId("signature1");
		parameters.setOriginX(10);
		parameters.setOriginY(10);
		parameters.setHeight(50);
		parameters.setWidth(50);
		DSSDocument withFirstField = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(withFirstField);

		parameters.setFieldId("signature2");
		Exception exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(withFirstField, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
	}

	@Test
	public void differentPagesTest() throws IOException {
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/empty-two-pages.pdf"));

		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setFieldId("signature1");
		parameters.setOriginX(10);
		parameters.setOriginY(10);
		parameters.setHeight(50);
		parameters.setWidth(50);
		parameters.setPage(1);
		DSSDocument withFirstField = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(withFirstField);

		parameters.setFieldId("signature2");
		Exception exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(withFirstField, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		parameters.setPage(2);
		DSSDocument withTwoFields = service.addNewSignatureField(withFirstField, parameters);

		assertEquals(2, service.getAvailableSignatureFields(withTwoFields).size());
	}

	@Test
	public void fieldInsideAnotherTest() throws IOException {
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
		parametersTwo.setHeight(50);
		parametersTwo.setWidth(50);
		parametersTwo.setFieldId("signature2");
		Exception exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(withFirstField, parametersTwo));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
	}

	@Test
	public void oneCornerOverlapTest() throws IOException {
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
		parametersTwo.setOriginX(75);
		parametersTwo.setOriginY(75);
		parametersTwo.setHeight(100);
		parametersTwo.setWidth(100);
		parametersTwo.setFieldId("signature2");
		Exception exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(withFirstField, parametersTwo));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
	}

	@Test
	public void twoCornersOverlapTest() throws IOException {
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
		parametersTwo.setOriginX(75);
		parametersTwo.setOriginY(25);
		parametersTwo.setHeight(50);
		parametersTwo.setWidth(50);
		parametersTwo.setFieldId("signature2");
		Exception exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(withFirstField, parametersTwo));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
	}

	@Test
	public void sameEdgeTest() throws IOException {
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
		parametersTwo.setOriginX(100);
		parametersTwo.setOriginY(0);
		parametersTwo.setHeight(100);
		parametersTwo.setWidth(100);
		parametersTwo.setFieldId("signature2");
		DSSDocument withSecondField = service.addNewSignatureField(withFirstField, parametersTwo);
		assertNotNull(withSecondField);

		assertEquals(2, service.getAvailableSignatureFields(withSecondField).size());

		parametersTwo.setOriginX(99);
		Exception exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(withFirstField, parametersTwo));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
	}

	@Test
	public void annotationOverlapTest() throws IOException {
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));

		SignatureFieldParameters parametersOne = new SignatureFieldParameters();
		parametersOne.setFieldId("signature1");
		parametersOne.setOriginX(150);
		parametersOne.setOriginY(150);
		parametersOne.setHeight(100);
		parametersOne.setWidth(100);
		Exception exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(documentToSign, parametersOne));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
	}

	@Test
	public void fieldOverCommentTest() throws IOException {
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/pdf-with-annotations.pdf"));

		SignatureFieldParameters parametersOne = new SignatureFieldParameters();
		parametersOne.setFieldId("signature1");
		parametersOne.setOriginX(0);
		parametersOne.setOriginY(0);
		parametersOne.setHeight(50);
		parametersOne.setWidth(50);
		Exception exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(documentToSign, parametersOne));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
	}

	@Test
	public void fieldOverTextNoteTest() throws IOException {
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/pdf-with-annotations.pdf"));

		SignatureFieldParameters parametersOne = new SignatureFieldParameters();
		parametersOne.setFieldId("signature1");
		parametersOne.setOriginX(0);
		parametersOne.setOriginY(100);
		parametersOne.setHeight(50);
		parametersOne.setWidth(50);
		Exception exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(documentToSign, parametersOne));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
	}

	@Test
	public void fieldOverDrawingTest() throws IOException {
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/pdf-with-annotations.pdf"));

		SignatureFieldParameters parametersOne = new SignatureFieldParameters();
		parametersOne.setFieldId("signature1");
		parametersOne.setOriginX(300);
		parametersOne.setOriginY(25);
		parametersOne.setHeight(50);
		parametersOne.setWidth(50);
		Exception exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(documentToSign, parametersOne));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
	}

	@Test
	public void fieldOverShapeTest() throws IOException {
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/pdf-with-annotations.pdf"));

		SignatureFieldParameters parametersOne = new SignatureFieldParameters();
		parametersOne.setFieldId("signature1");
		parametersOne.setOriginX(0);
		parametersOne.setOriginY(200);
		parametersOne.setHeight(50);
		parametersOne.setWidth(50);
		Exception exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(documentToSign, parametersOne));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		parametersOne.setOriginX(0);
		parametersOne.setOriginY(400);
		DSSDocument document = service.addNewSignatureField(documentToSign, parametersOne);
		assertNotNull(document);
	}

	@Test
	public void fieldsOverlapWithRotatedDocTest() throws IOException {
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_90.pdf"));

		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setFieldId("signature1");
		parameters.setOriginX(50);
		parameters.setOriginY(100);
		parameters.setHeight(50);
		parameters.setWidth(100);
		DSSDocument doc90Degrees = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(doc90Degrees);

		parameters.setFieldId("signature2");
		Exception exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(doc90Degrees, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		signatureParameters.getImageParameters().getFieldParameters().setFieldId(null);
		signatureParameters.getImageParameters().setRotation(VisualSignatureRotation.AUTOMATIC);
		DSSDocument signed = signAndValidate(doc90Degrees);
		assertNotNull(signed);

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
		signatureParameters.getImageParameters().setRotation(VisualSignatureRotation.NONE);
		signed = signAndValidate(signed);
		assertNotNull(signed);
		//signed.save("target/doc90Degrees.pdf");

		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_180.pdf"));

		parameters.setFieldId("signature1");
		DSSDocument doc180Degrees = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(doc180Degrees);

		parameters.setFieldId("signature2");
		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(doc180Degrees, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		signatureParameters.getImageParameters().getFieldParameters().setFieldId(null);
		signatureParameters.getImageParameters().setRotation(VisualSignatureRotation.AUTOMATIC);
		signed = signAndValidate(doc180Degrees);
		assertNotNull(signed);

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
		signatureParameters.getImageParameters().setRotation(VisualSignatureRotation.NONE);
		signed = signAndValidate(signed);
		assertNotNull(signed);
		//signed.save("target/doc180Degrees.pdf");

		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_270.pdf"));

		parameters.setFieldId("signature1");
		DSSDocument doc270Degrees = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(doc270Degrees);

		parameters.setFieldId("signature2");
		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(doc270Degrees, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		signatureParameters.getImageParameters().getFieldParameters().setFieldId(null);
		signatureParameters.getImageParameters().setRotation(VisualSignatureRotation.AUTOMATIC);
		signed = signAndValidate(doc270Degrees);
		assertNotNull(signed);

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
		signatureParameters.getImageParameters().setRotation(VisualSignatureRotation.NONE);
		signed = signAndValidate(signed);
		assertNotNull(signed);
		//signed.save("target/doc270Degrees.pdf");

		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_-90.pdf"));

		parameters.setFieldId("signature1");
		DSSDocument docMinus90Degrees = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(docMinus90Degrees);

		parameters.setFieldId("signature2");
		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(docMinus90Degrees, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		signatureParameters.getImageParameters().getFieldParameters().setFieldId(null);
		signatureParameters.getImageParameters().setRotation(VisualSignatureRotation.AUTOMATIC);
		signed = signAndValidate(docMinus90Degrees);
		assertNotNull(signed);

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
		signatureParameters.getImageParameters().setRotation(VisualSignatureRotation.NONE);
		signed = signAndValidate(signed);
		assertNotNull(signed);
		//signed.save("target/docMinus90Degrees.pdf");

		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_-180.pdf"));

		parameters.setFieldId("signature1");
		DSSDocument docMinus180Degrees = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(docMinus180Degrees);

		parameters.setFieldId("signature2");
		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(docMinus180Degrees, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		signatureParameters.getImageParameters().getFieldParameters().setFieldId(null);
		signatureParameters.getImageParameters().setRotation(VisualSignatureRotation.AUTOMATIC);
		signed = signAndValidate(docMinus180Degrees);
		assertNotNull(signed);

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
		signatureParameters.getImageParameters().setRotation(VisualSignatureRotation.NONE);
		signed = signAndValidate(signed);
		assertNotNull(signed);
		//signed.save("target/docMinus180Degrees.pdf");

		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_-270.pdf"));

		parameters.setFieldId("signature1");
		DSSDocument docMinus270Degrees = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(docMinus270Degrees);

		parameters.setFieldId("signature2");
		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(docMinus270Degrees, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		signatureParameters.getImageParameters().getFieldParameters().setFieldId(null);
		signatureParameters.getImageParameters().setRotation(VisualSignatureRotation.AUTOMATIC);
		signed = signAndValidate(docMinus270Degrees);
		assertNotNull(signed);

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
		signatureParameters.getImageParameters().setRotation(VisualSignatureRotation.NONE);
		signed = signAndValidate(signed);
		assertNotNull(signed);
		//signed.save("target/docMinus270Degrees.pdf");
	}

	@Test
	public void fieldsOverlapWithCustomRotationTest() throws IOException {
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(50);
		fieldParameters.setOriginY(100);
		fieldParameters.setHeight(50);
		fieldParameters.setWidth(100);

		signatureParameters.getImageParameters().setTextParameters(textParameters);
		signatureParameters.getImageParameters().setFieldParameters(fieldParameters);
		signatureParameters.getImageParameters().setRotation(VisualSignatureRotation.ROTATE_90);

		DSSDocument doc90Degrees = signAndValidate(documentToSign);
		assertNotNull(doc90Degrees);

		Exception exception = assertThrows(AlertException.class,
				() -> signAndValidate(doc90Degrees));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		signatureParameters.getImageParameters().setRotation(VisualSignatureRotation.ROTATE_180);

		DSSDocument doc180Degrees = signAndValidate(doc90Degrees);
		assertNotNull(doc180Degrees);

		exception = assertThrows(AlertException.class,
				() -> signAndValidate(doc180Degrees));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		signatureParameters.getImageParameters().setRotation(VisualSignatureRotation.ROTATE_270);

		DSSDocument doc270Degrees = signAndValidate(doc180Degrees);
		assertNotNull(doc270Degrees);

		exception = assertThrows(AlertException.class,
				() -> signAndValidate(doc270Degrees));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		signatureParameters.getImageParameters().setRotation(VisualSignatureRotation.NONE);

		exception = assertThrows(AlertException.class,
				() -> signAndValidate(doc270Degrees));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		signatureParameters.getImageParameters().setRotation(VisualSignatureRotation.AUTOMATIC);

		exception = assertThrows(AlertException.class,
				() -> signAndValidate(doc270Degrees));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
	}

	@Test
	public void signOutOfPageDimensionsWithRotatedDocumentsTest() throws IOException {
		DSSDocument doc90Degrees = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_90.pdf"));

		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setFieldId("signature1");
		parameters.setOriginX(500);
		parameters.setOriginY(100);
		parameters.setHeight(50);
		parameters.setWidth(100);

		Exception exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(doc90Degrees, parameters));
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		DSSDocument doc180Degrees = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_180.pdf"));

		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(doc180Degrees, parameters));
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		DSSDocument doc270Degrees = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_270.pdf"));

		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(doc270Degrees, parameters));
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		DSSDocument docMinus90Degrees = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_-90.pdf"));

		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(docMinus90Degrees, parameters));
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		DSSDocument docMinus180Degrees = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_-180.pdf"));

		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(docMinus180Degrees, parameters));
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		DSSDocument docMinus270Degrees = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_-270.pdf"));

		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(docMinus270Degrees, parameters));
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));
	}

	@Test
	public void testWithTempFileResources() throws IOException {
		service.setResourcesHandlerBuilder(new TempFileResourcesHandlerBuilder());

		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/EmptyPage.pdf"));

		// Add a signature field first
		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setFieldId("test");
		parameters.setOriginX(10);
		parameters.setOriginY(10);
		parameters.setHeight(50);
		parameters.setWidth(50);
		DSSDocument doc = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(doc);
		assertTrue(doc instanceof FileDocument);

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("test");

		DSSDocument signed = signAndValidate(doc);
		assertNotNull(signed);
		assertTrue(signed instanceof FileDocument);
	}

	private DSSDocument signAndValidate(DSSDocument documentToSign) throws IOException {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		// signedDocument.save("target/test.pdf");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getSignatures()));
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			assertTrue(signature.isSignatureIntact());
			assertTrue(signature.isSignatureValid());
			assertTrue(Utils.isCollectionNotEmpty(signature.getDigestMatchers()));
			for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
				assertTrue(digestMatcher.isDataFound());
				assertTrue(digestMatcher.isDataIntact());
			}
		}

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));

		return signedDocument;
	}

	private int countStringOccurrence(DSSDocument document, String textToCheck) {
		int counter = 0;
		String line;
		try (InputStream is = document.openStream();
				InputStreamReader isr = new InputStreamReader(is);
				BufferedReader br = new BufferedReader(isr)) {
			while ((line = br.readLine()) != null) {
				if (line.contains(textToCheck)) {
					counter++;
				}
			}
		} catch (Exception e) {
			throw new DSSException(e);
		}
		return counter;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
