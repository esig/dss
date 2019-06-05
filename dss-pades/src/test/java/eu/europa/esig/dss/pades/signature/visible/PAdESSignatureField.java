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
package eu.europa.esig.dss.pades.signature.visible;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.awt.Color;
import java.io.IOException;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class PAdESSignatureField extends PKIFactoryAccess {

	private PAdESService service;
	private PAdESSignatureParameters signatureParameters;

	@Before
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
		signatureParameters.setSignatureImageParameters(imageParameters);

		service = new PAdESService(getCompleteCertificateVerifier());
	}

	@Test
	public void testGeneratedTextOnly() throws IOException {

		signatureParameters.setSignatureFieldId("Signature1");

		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));
		signAndValidate(documentToSign);
	}

	@Test
	public void testSignTwice() throws IOException {

		// Add second field first
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));

		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setName("test");
		parameters.setOriginX(10);
		parameters.setOriginY(10);
		parameters.setHeight(50);
		parameters.setWidth(50);
		DSSDocument doc = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(doc);

		// Sign twice

		signatureParameters.setSignatureFieldId("Signature1");

		DSSDocument doc2 = signAndValidate(doc);
		assertNotNull(doc2);

		signatureParameters.setSignatureFieldId("test");

		DSSDocument doc3 = signAndValidate(doc2);
		assertNotNull(doc3);
	}
	
	@Test
	public void testSignTwoFields() throws IOException {

		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));
		
		// add first field
		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setName("signature1");
		parameters.setOriginX(10);
		parameters.setOriginY(10);
		parameters.setHeight(50);
		parameters.setWidth(50);
		DSSDocument withFirstField = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(withFirstField);

		// add second field
		parameters = new SignatureFieldParameters();
		parameters.setName("signature2");
		parameters.setOriginX(100);
		parameters.setOriginY(10);
		parameters.setHeight(50);
		parameters.setWidth(50);
		DSSDocument secondField = service.addNewSignatureField(withFirstField, parameters);
		assertNotNull(secondField);
		
		// sign first field
		signatureParameters.setSignatureFieldId("signature1");
		DSSDocument firstSigned = signAndValidate(secondField);
		assertNotNull(firstSigned);

		// sign second field
		signatureParameters.setSignatureFieldId("signature2");
		DSSDocument secondSigned = signAndValidate(firstSigned);
		assertNotNull(secondSigned);
		
	}
	
	@Test
	public void createAndSignConsequently() throws IOException {
		
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));
		
		// add field and sign
		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setName("signature1");
		parameters.setOriginX(10);
		parameters.setOriginY(10);
		parameters.setHeight(50);
		parameters.setWidth(50);
		DSSDocument withFirstField = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(withFirstField);

		signatureParameters.setSignatureFieldId("signature1");
		DSSDocument firstSigned = signAndValidate(withFirstField);
		assertNotNull(firstSigned);
		
		// add a new field and second sign
		parameters = new SignatureFieldParameters();
		parameters.setName("signature2");
		parameters.setOriginX(100);
		parameters.setOriginY(10);
		parameters.setHeight(50);
		parameters.setWidth(50);
		DSSDocument secondField = service.addNewSignatureField(firstSigned, parameters);
		assertNotNull(secondField);

		signatureParameters.setSignatureFieldId("signature2");
		DSSDocument secondSigned = signAndValidate(secondField);
		assertNotNull(secondSigned);

	}
	
	@Test
	public void createFieldInEmptyDocument() throws IOException {
		
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/EmptyPage.pdf"));
		
		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setName("signature1");
		parameters.setOriginX(10);
		parameters.setOriginY(10);
		parameters.setHeight(50);
		parameters.setWidth(50);
		DSSDocument withFirstField = service.addNewSignatureField(documentToSign, parameters);
		assertNotNull(withFirstField);

		signatureParameters.setSignatureFieldId("signature1");
		DSSDocument firstSigned = signAndValidate(withFirstField);
		assertNotNull(firstSigned);
		
	}

	@Test(expected = DSSException.class)
	public void testSignTwiceSameField() throws IOException {

		signatureParameters.setSignatureFieldId("Signature1");

		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));
		DSSDocument doc = signAndValidate(documentToSign);
		assertNotNull(doc);

		signAndValidate(doc);
	}

	@Test(expected = DSSException.class)
	public void testFieldNotFound() throws IOException {

		signatureParameters.setSignatureFieldId("not-found");

		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));
		signAndValidate(documentToSign);
	}

	private DSSDocument signAndValidate(DSSDocument documentToSign) throws IOException {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		// signedDocument.save("target/test.pdf");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
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

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
