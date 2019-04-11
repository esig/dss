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
package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class DSS920ValidationWithDigestTest extends PKIFactoryAccess {

	// PROVIDE WRONG DIGEST WITH WRONG ALGO
	@Test(expected = DSSException.class)
	public void testValidationWithWrongDigest() throws Exception {

		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.xml"));

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());

		XAdESSignatureParameters params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setDigestAlgorithm(DigestAlgorithm.SHA256);
		params.setSignaturePackaging(SignaturePackaging.DETACHED);
		params.setSigningCertificate(getSigningCert());

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);


		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());

		// Provide only the digest value
		List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
		DigestDocument digestDocument = new DigestDocument(DigestAlgorithm.SHA1, toBeSigned.getDigest(DigestAlgorithm.SHA1));
		digestDocument.setName("sample.xml");
		detachedContents.add(digestDocument);
		validator.setDetachedContents(detachedContents);

		Reports reports = validator.validateDocument();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		assertTrue(signature.isDocHashOnly());
		assertFalse(signature.isHashOnly());
		
	}

	@Test
	public void testValidationWithDigest() throws Exception {

		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.xml"));

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());

		XAdESSignatureParameters params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setDigestAlgorithm(DigestAlgorithm.SHA256);
		params.setSignaturePackaging(SignaturePackaging.DETACHED);
		params.setSigningCertificate(getSigningCert());

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());

		// Provide only the digest value
		List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
		DigestDocument digestDocument = new DigestDocument(DigestAlgorithm.SHA256, toBeSigned.getDigest(DigestAlgorithm.SHA256));
		digestDocument.setName("sample.xml");
		detachedContents.add(digestDocument);
		validator.setDetachedContents(detachedContents);

		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isBLevelTechnicallyValid());
		
		assertTrue(signature.isDocHashOnly());
		assertFalse(signature.isHashOnly());
		
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		assertNotNull(signatureScopes);
		XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);
		assertNotNull(xmlSignatureScope);
		assertNotNull(xmlSignatureScope.getName());
		assertNotNull(xmlSignatureScope.getScope());
		assertNotNull(xmlSignatureScope.getSignedData());;
		assertNotNull(xmlSignatureScope.getSignedData().getDigestAlgoAndValue());
		assertNotNull(xmlSignatureScope.getSignedData().getDigestAlgoAndValue().getDigestMethod());
		assertNotNull(xmlSignatureScope.getSignedData().getDigestAlgoAndValue().getDigestValue());
		
		assertTrue(Arrays.equals(xmlSignatureScope.getSignedData().getDigestAlgoAndValue().getDigestValue(), 
				Utils.fromBase64(toBeSigned.getDigest(DigestAlgorithm.forName(xmlSignatureScope.getSignedData().getDigestAlgoAndValue().getDigestMethod())))
				));
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
