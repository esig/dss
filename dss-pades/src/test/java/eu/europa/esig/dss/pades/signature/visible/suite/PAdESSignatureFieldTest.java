/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.signature.visible.suite;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
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
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PAdESSignatureFieldTest extends PKIFactoryAccess {

	private PAdESService service;
	private PAdESSignatureParameters signatureParameters;
	private PAdESTimestampParameters timestampParameters;

	@BeforeEach
	void init() throws Exception {

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

		timestampParameters = new PAdESTimestampParameters();

		imageParameters = new SignatureImageParameters();
		textParameters = new SignatureImageTextParameters();
		textParameters.setText("My timestamp");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);
		timestampParameters.setImageParameters(imageParameters);

		service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	@Test
	void testGeneratedTextOnly() throws IOException {

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("Signature1");

		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));
		signAndValidate(documentToSign);
	}

	@Test
	void testSignTwice() throws IOException {

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
	void testSignTwoFields() throws IOException {

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
		DSSDocument secondSigned = sign(firstSigned);
		assertNotNull(secondSigned);

		assertEquals(6, countStringOccurrence(secondSigned, "startxref"));
		assertEquals(6, countStringOccurrence(secondSigned, "%%EOF"));

		Reports reports = validate(secondSigned, false);
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		boolean extendedSugFound = false;
		boolean lastSigFound = false;
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			if (signatureWrapper.arePdfObjectModificationsDetected()) {
				PDFRevisionWrapper pdfRevision = signatureWrapper.getPDFRevision();
				assertFalse(Utils.isCollectionNotEmpty(pdfRevision.getPdfExtensionChanges()));
				assertTrue(Utils.isCollectionNotEmpty(pdfRevision.getPdfSignatureOrFormFillChanges()));
				assertFalse(Utils.isCollectionNotEmpty(pdfRevision.getPdfAnnotationChanges()));
				assertFalse(Utils.isCollectionNotEmpty(pdfRevision.getPdfUndefinedChanges()));

				extendedSugFound = true;

			} else  {
				PDFRevisionWrapper pdfRevision = signatureWrapper.getPDFRevision();
				assertFalse(Utils.isCollectionNotEmpty(pdfRevision.getPdfExtensionChanges()));
				assertFalse(Utils.isCollectionNotEmpty(pdfRevision.getPdfSignatureOrFormFillChanges()));
				assertFalse(Utils.isCollectionNotEmpty(pdfRevision.getPdfAnnotationChanges()));
				assertFalse(Utils.isCollectionNotEmpty(pdfRevision.getPdfUndefinedChanges()));

				lastSigFound = true;
			}
		}
		assertTrue(extendedSugFound);
		assertTrue(lastSigFound);
	}

	@Test
	void createAndSignConsequently() throws IOException {

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
	void createFieldInEmptyDocument() throws IOException {

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
	void testSignTwiceSameField() throws IOException {
		signatureParameters.getImageParameters().getFieldParameters().setFieldId("Signature1");

		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));
		DSSDocument doc = signAndValidate(documentToSign);
		assertNotNull(doc);

		assertThrows(IllegalArgumentException.class, () -> signAndValidate(doc));
	}

	@Test
	void testFieldNotFound() throws IOException {
		signatureParameters.getImageParameters().getFieldParameters().setFieldId("not-found");

		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));
		assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign));
	}

	@Test
	void fieldsOverlapTest() throws IOException {
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
	void differentPagesTest() throws IOException {
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
	void fieldInsideAnotherTest() throws IOException {
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
	void oneCornerOverlapTest() throws IOException {
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
	void twoCornersOverlapTest() throws IOException {
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
	void sameEdgeTest() throws IOException {
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
	void annotationOverlapTest() throws IOException {
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
	void fieldOverCommentTest() throws IOException {
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
	void fieldOverTextNoteTest() throws IOException {
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
	void fieldOverDrawingTest() throws IOException {
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
	void fieldOverShapeTest() throws IOException {
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
	void fieldsOverlapWithRotatedDocTest() throws IOException {
		// NOTE: skip object modification detection due to OpenPdf wrong processing
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
		signatureParameters.getImageParameters().getFieldParameters().setRotation(VisualSignatureRotation.AUTOMATIC);
		DSSDocument signed = sign(doc90Degrees);
		assertNotNull(signed);
		validate(signed, true);

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
		signatureParameters.getImageParameters().getFieldParameters().setRotation(VisualSignatureRotation.NONE);
		signed = sign(signed);
		assertNotNull(signed);
		//signed.save("target/doc90Degrees.pdf");
		validate(signed, true);

		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_180.pdf"));

		parameters.setFieldId("signature1");
		DSSDocument doc180Degrees = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(doc180Degrees);

		parameters.setFieldId("signature2");
		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(doc180Degrees, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		signatureParameters.getImageParameters().getFieldParameters().setFieldId(null);
		signatureParameters.getImageParameters().getFieldParameters().setRotation(VisualSignatureRotation.AUTOMATIC);
		signed = sign(doc180Degrees);
		assertNotNull(signed);
		validate(signed, true);

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
		signatureParameters.getImageParameters().getFieldParameters().setRotation(VisualSignatureRotation.NONE);
		signed = sign(signed);
		assertNotNull(signed);
		//signed.save("target/doc180Degrees.pdf");
		validate(signed, true);

		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_270.pdf"));

		parameters.setFieldId("signature1");
		DSSDocument doc270Degrees = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(doc270Degrees);

		parameters.setFieldId("signature2");
		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(doc270Degrees, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		signatureParameters.getImageParameters().getFieldParameters().setFieldId(null);
		signatureParameters.getImageParameters().getFieldParameters().setRotation(VisualSignatureRotation.AUTOMATIC);
		signed = sign(doc270Degrees);
		assertNotNull(signed);
		validate(signed, true);

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
		signatureParameters.getImageParameters().getFieldParameters().setRotation(VisualSignatureRotation.NONE);
		signed = sign(signed);
		assertNotNull(signed);
		//signed.save("target/doc270Degrees.pdf");
		validate(signed, true);

		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_-90.pdf"));

		parameters.setFieldId("signature1");
		DSSDocument docMinus90Degrees = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(docMinus90Degrees);

		parameters.setFieldId("signature2");
		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(docMinus90Degrees, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		signatureParameters.getImageParameters().getFieldParameters().setFieldId(null);
		signatureParameters.getImageParameters().getFieldParameters().setRotation(VisualSignatureRotation.AUTOMATIC);
		signed = sign(docMinus90Degrees);
		assertNotNull(signed);
		validate(signed, true);

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
		signatureParameters.getImageParameters().getFieldParameters().setRotation(VisualSignatureRotation.NONE);
		signed = sign(signed);
		assertNotNull(signed);
		//signed.save("target/docMinus90Degrees.pdf");
		validate(signed, true);

		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_-180.pdf"));

		parameters.setFieldId("signature1");
		DSSDocument docMinus180Degrees = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(docMinus180Degrees);

		parameters.setFieldId("signature2");
		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(docMinus180Degrees, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		signatureParameters.getImageParameters().getFieldParameters().setFieldId(null);
		signatureParameters.getImageParameters().getFieldParameters().setRotation(VisualSignatureRotation.AUTOMATIC);
		signed = sign(docMinus180Degrees);
		assertNotNull(signed);
		validate(signed, true);

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
		signatureParameters.getImageParameters().getFieldParameters().setRotation(VisualSignatureRotation.NONE);
		signed = sign(signed);
		assertNotNull(signed);
		//signed.save("target/docMinus180Degrees.pdf");
		validate(signed, true);

		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/test_-270.pdf"));

		parameters.setFieldId("signature1");
		DSSDocument docMinus270Degrees = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(docMinus270Degrees);

		parameters.setFieldId("signature2");
		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(docMinus270Degrees, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		signatureParameters.getImageParameters().getFieldParameters().setFieldId(null);
		signatureParameters.getImageParameters().getFieldParameters().setRotation(VisualSignatureRotation.AUTOMATIC);
		signed = sign(docMinus270Degrees);
		assertNotNull(signed);
		validate(signed, true);

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
		signatureParameters.getImageParameters().getFieldParameters().setRotation(VisualSignatureRotation.NONE);
		signed = sign(signed);
		assertNotNull(signed);
		//signed.save("target/docMinus270Degrees.pdf");
		validate(signed, true);
	}

	@Test
	void noRotationFlagTest() throws IOException {
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/annots-no-rotate.pdf"));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setPage(1);

		fieldParameters.setOriginX(0);
		fieldParameters.setOriginY(0);
		fieldParameters.setWidth(40);
		fieldParameters.setHeight(60);
		fieldParameters.setRotation(VisualSignatureRotation.ROTATE_270);

		DSSDocument noRotate90Degrees = service.addNewSignatureField(documentToSign, fieldParameters);
		assertNotNull(noRotate90Degrees);

		Exception exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(noRotate90Degrees, fieldParameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		fieldParameters.setOriginX(20);
		fieldParameters.setOriginY(20);
		fieldParameters.setWidth(40);
		fieldParameters.setHeight(20);
		fieldParameters.setRotation(VisualSignatureRotation.ROTATE_270);

		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(documentToSign, fieldParameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		fieldParameters.setPage(2);

		fieldParameters.setOriginX(280);
		fieldParameters.setOriginY(60);
		fieldParameters.setWidth(80);
		fieldParameters.setHeight(40);
		fieldParameters.setRotation(VisualSignatureRotation.AUTOMATIC);

		DSSDocument noRotate180Degrees = service.addNewSignatureField(noRotate90Degrees, fieldParameters);
		assertNotNull(noRotate180Degrees);

		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(noRotate180Degrees, fieldParameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		fieldParameters.setOriginX(280);
		fieldParameters.setOriginY(100);
		fieldParameters.setWidth(80);
		fieldParameters.setHeight(40);
		fieldParameters.setRotation(VisualSignatureRotation.AUTOMATIC);

		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(noRotate90Degrees, fieldParameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		fieldParameters.setPage(3);

		fieldParameters.setOriginX(412);
		fieldParameters.setOriginY(300);
		fieldParameters.setWidth(40);
		fieldParameters.setHeight(80);
		fieldParameters.setRotation(VisualSignatureRotation.AUTOMATIC);

		DSSDocument noRotate270Degrees = service.addNewSignatureField(noRotate180Degrees, fieldParameters);
		assertNotNull(noRotate270Degrees);

		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(noRotate270Degrees, fieldParameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		fieldParameters.setOriginX(400);
		fieldParameters.setOriginY(320);
		fieldParameters.setWidth(40);
		fieldParameters.setHeight(80);
		fieldParameters.setRotation(VisualSignatureRotation.AUTOMATIC);

		exception = assertThrows(AlertException.class,
				() -> service.addNewSignatureField(noRotate180Degrees, fieldParameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
	}

	@Test
	void fieldsOverlapWithCustomRotationTest() throws IOException {
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(50);
		fieldParameters.setOriginY(100);
		fieldParameters.setHeight(50);
		fieldParameters.setWidth(100);
		fieldParameters.setRotation(VisualSignatureRotation.ROTATE_90);

		signatureParameters.getImageParameters().setTextParameters(textParameters);
		signatureParameters.getImageParameters().setFieldParameters(fieldParameters);

		DSSDocument doc90Degrees = signAndValidate(documentToSign);
		assertNotNull(doc90Degrees);

		Exception exception = assertThrows(AlertException.class,
				() -> signAndValidate(doc90Degrees));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		fieldParameters.setRotation(VisualSignatureRotation.ROTATE_180);

		DSSDocument doc180Degrees = signAndValidate(doc90Degrees);
		assertNotNull(doc180Degrees);

		exception = assertThrows(AlertException.class,
				() -> signAndValidate(doc180Degrees));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		fieldParameters.setRotation(VisualSignatureRotation.ROTATE_270);

		DSSDocument doc270Degrees = signAndValidate(doc180Degrees);
		assertNotNull(doc270Degrees);

		exception = assertThrows(AlertException.class,
				() -> signAndValidate(doc270Degrees));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		fieldParameters.setRotation(VisualSignatureRotation.NONE);

		exception = assertThrows(AlertException.class,
				() -> signAndValidate(doc270Degrees));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		fieldParameters.setRotation(VisualSignatureRotation.AUTOMATIC);

		exception = assertThrows(AlertException.class,
				() -> signAndValidate(doc270Degrees));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
	}

	@Test
	void signOutOfPageDimensionsWithRotatedDocumentsTest() throws IOException {
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
	void testWithTempFileResources() throws IOException {
		IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();
		pdfObjFactory.setResourcesHandlerBuilder(new TempFileResourcesHandlerBuilder());
		service.setPdfObjFactory(pdfObjFactory);

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

	// see DSS-3269
	@Test
	void testSignFieldWithWrongPage() throws IOException {
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/documentEmptySignature.pdf"));

		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature");
		DSSDocument doc = signAndValidate(documentToSign);
		assertNotNull(doc);

		// both should work
		signatureParameters.getImageParameters().getFieldParameters().setPage(1);
		doc = signAndValidate(documentToSign);
		assertNotNull(doc);

		// evaluate signature field presence
		signatureParameters.getImageParameters().getFieldParameters().setFieldId(null);
		signatureParameters.getImageParameters().getFieldParameters().setHeight(100);
		signatureParameters.getImageParameters().getFieldParameters().setWidth(200);
		signatureParameters.getImageParameters().getFieldParameters().setPage(1);

		DSSDocument doubleSigned = signAndValidate(doc);
		assertNotNull(doubleSigned);
		doubleSigned.save("target/doubleSigned.pdf");

		signatureParameters.getImageParameters().getFieldParameters().setPage(2);
		Exception exception = assertThrows(AlertException.class,
				() -> signAndValidate(doubleSigned));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
	}

	@Test
	void testTimestampSignatureField() throws IOException {
		DSSDocument document = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));

		timestampParameters.getImageParameters().getFieldParameters().setFieldId("Signature1");
		DSSDocument timestampedDocument = timestampAndValidate(document);

		assertTrue(Utils.isCollectionEmpty(service.getAvailableSignatureFields(timestampedDocument)));
	}

	@Test
	void testTLevelAugmentationWithVisibleTimestamp() throws IOException {
		DSSDocument document = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));

		signatureParameters.setImageParameters(null);
		DSSDocument signedDocument = signAndValidate(document);

		timestampParameters.getImageParameters().getFieldParameters().setFieldId("Signature1");
		signatureParameters.setSignatureTimestampParameters(timestampParameters);
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);

		DSSDocument extendedDocument = service.extendDocument(signedDocument, signatureParameters);
		assertTrue(Utils.isCollectionEmpty(service.getAvailableSignatureFields(extendedDocument)));
	}

	@Test
	void testLTALevelWithVisibleSignatureAndTimestamp() throws IOException {
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

		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");

		timestampParameters.getImageParameters().getFieldParameters().setFieldId("signature2");
		signatureParameters.setArchiveTimestampParameters(timestampParameters);

		DSSDocument signedDocument = signAndValidate(withSecondField);
		assertNotNull(signedDocument);
		assertTrue(Utils.isCollectionEmpty(service.getAvailableSignatureFields(signedDocument)));
	}

	@Test
	void testLTALevelWithVisibleSignatureAndTimestampSameField() throws IOException {
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

		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");

		timestampParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
		signatureParameters.setArchiveTimestampParameters(timestampParameters);

		Exception exception = assertThrows(IllegalArgumentException.class,
				() -> signAndValidate(withSecondField));
		assertTrue(exception.getMessage().contains("signature1"));
	}

	@Test
	void testNegativeCoordinates() throws IOException {
		// Add to an empty doc
		DSSDocument emptyDoc = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/coordinates/doc-negative-coordinates.pdf"));

		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setFieldId("signature1");
		parameters.setOriginX(10);
		parameters.setOriginY(10);
		parameters.setHeight(50);
		parameters.setWidth(50);
		parameters.setRotation(VisualSignatureRotation.NONE);

		DSSDocument oneSigFieldDoc = service.addNewSignatureField(emptyDoc, parameters);
		assertNotNull(oneSigFieldDoc);

		Exception exception = assertThrows(AlertException.class, () -> service.addNewSignatureField(oneSigFieldDoc, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		parameters.setFieldId("signature2");
		parameters.setRotation(VisualSignatureRotation.ROTATE_90);

		DSSDocument twoSigFieldDoc = service.addNewSignatureField(oneSigFieldDoc, parameters);
		assertNotNull(twoSigFieldDoc);

        signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
        DSSDocument signed = signAndValidate(twoSigFieldDoc);
        assertNotNull(signed);

		// Add to a doc with existing sig field
		DSSDocument docWithField = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/check/negative_coordinates_NONE.pdf"));

		parameters.setFieldId("signature1");
		parameters.setRotation(VisualSignatureRotation.NONE);

		exception = assertThrows(AlertException.class, () -> service.addNewSignatureField(docWithField, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		parameters.setFieldId("signature2");
		parameters.setRotation(VisualSignatureRotation.ROTATE_90);

		twoSigFieldDoc = service.addNewSignatureField(docWithField, parameters);
		assertNotNull(twoSigFieldDoc);

        signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature2");
        signed = signAndValidate(twoSigFieldDoc);
        assertNotNull(signed);

		// Add to a doc with existing sig field
		DSSDocument docWithFieldAndRotation = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/check/negative_coordinates_ROTATE_90.pdf"));

		parameters.setFieldId("signature1");
		parameters.setRotation(VisualSignatureRotation.NONE);

		twoSigFieldDoc = service.addNewSignatureField(docWithFieldAndRotation, parameters);
		assertNotNull(twoSigFieldDoc);

		parameters.setFieldId("signature2");
		parameters.setRotation(VisualSignatureRotation.ROTATE_90);

		exception = assertThrows(AlertException.class, () -> service.addNewSignatureField(docWithFieldAndRotation, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

        signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
        signed = signAndValidate(twoSigFieldDoc);
        assertNotNull(signed);
	}

	@Test
	void testPositiveCoordinates() throws IOException {
		// Add to an empty doc
		DSSDocument emptyDoc = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/coordinates/doc-positive-coordinates.pdf"));

		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setFieldId("signature1");
		parameters.setOriginX(10);
		parameters.setOriginY(10);
		parameters.setHeight(50);
		parameters.setWidth(50);
		parameters.setRotation(VisualSignatureRotation.NONE);

		DSSDocument oneSigFieldDoc = service.addNewSignatureField(emptyDoc, parameters);
		assertNotNull(oneSigFieldDoc);

		Exception exception = assertThrows(AlertException.class, () -> service.addNewSignatureField(oneSigFieldDoc, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		parameters.setFieldId("signature2");
		parameters.setRotation(VisualSignatureRotation.ROTATE_90);

		DSSDocument twoSigFieldDoc = service.addNewSignatureField(oneSigFieldDoc, parameters);
		assertNotNull(twoSigFieldDoc);

        signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
        DSSDocument signed = signAndValidate(twoSigFieldDoc);
        assertNotNull(signed);

		// Add to a doc with existing sig field
		DSSDocument docWithField = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/check/positive_coordinates_NONE.pdf"));

		parameters.setFieldId("signature1");
		parameters.setRotation(VisualSignatureRotation.NONE);

		exception = assertThrows(AlertException.class, () -> service.addNewSignatureField(docWithField, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

		parameters.setFieldId("signature2");
		parameters.setRotation(VisualSignatureRotation.ROTATE_90);

		twoSigFieldDoc = service.addNewSignatureField(docWithField, parameters);
		assertNotNull(twoSigFieldDoc);

        signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature2");
        signed = signAndValidate(twoSigFieldDoc);
        assertNotNull(signed);

		// Add to a doc with existing sig field
		DSSDocument docWithFieldAndRotation = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/check/positive_coordinates_ROTATE_90.pdf"));

		parameters.setFieldId("signature1");
		parameters.setRotation(VisualSignatureRotation.NONE);

		twoSigFieldDoc = service.addNewSignatureField(docWithFieldAndRotation, parameters);
		assertNotNull(twoSigFieldDoc);

        signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
        signed = signAndValidate(twoSigFieldDoc);
        assertNotNull(signed);

		parameters.setFieldId("signature2");
		parameters.setRotation(VisualSignatureRotation.ROTATE_90);

		exception = assertThrows(AlertException.class, () -> service.addNewSignatureField(docWithFieldAndRotation, parameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
	}

	private DSSDocument signAndValidate(DSSDocument documentToSign) throws IOException {
		DSSDocument signedDocument = sign(documentToSign);
		validate(signedDocument, false);
		return signedDocument;
	}

	private DSSDocument sign(DSSDocument documentToSign) throws IOException {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		// signedDocument.save("target/test.pdf");
		return signedDocument;
	}

	private DSSDocument timestampAndValidate(DSSDocument document) throws IOException {
		DSSDocument timestampedDocument = timestamp(document);
		validate(timestampedDocument, false);
		return timestampedDocument;
	}

	private DSSDocument timestamp(DSSDocument document) throws IOException {
		DSSDocument timestampedDocument = service.timestamp(document, timestampParameters);
		// timestampedDocument.save("target/timestamped.pdf");
		return timestampedDocument;
	}

	private Reports validate(DSSDocument signedDocument, boolean skipObjectModification) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getSignatures()) ||
				Utils.isCollectionNotEmpty(diagnosticData.getTimestampList()));
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			assertTrue(signature.isSignatureIntact());
			assertTrue(signature.isSignatureValid());
			assertTrue(signature.isBLevelTechnicallyValid());
			assertTrue(Utils.isCollectionNotEmpty(signature.getDigestMatchers()));
			for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
				assertTrue(digestMatcher.isDataFound());
				assertTrue(digestMatcher.isDataIntact());
			}
			assertFalse(signature.arePdfModificationsDetected());
			assertTrue(skipObjectModification || signature.getPdfUndefinedChanges().isEmpty());
		}
		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			assertTrue(timestamp.isSignatureIntact());
			assertTrue(timestamp.isSignatureValid());
			assertTrue(Utils.isCollectionNotEmpty(timestamp.getDigestMatchers()));
			for (XmlDigestMatcher digestMatcher : timestamp.getDigestMatchers()) {
				assertTrue(digestMatcher.isDataFound());
				assertTrue(digestMatcher.isDataIntact());
			}
			assertFalse(timestamp.arePdfModificationsDetected());
			assertTrue(skipObjectModification || timestamp.getPdfUndefinedChanges().isEmpty());
		}

		return reports;
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
