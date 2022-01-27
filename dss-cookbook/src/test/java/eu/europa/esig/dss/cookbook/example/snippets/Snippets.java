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
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.JKSSignatureToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Snippets {

	@SuppressWarnings({ "null" })
	public void demo() {

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		CertificateToken certificateToken = new CertificateToken(null);
		List<CertificateToken> certificateChain = new LinkedList<>();

		// tag::demoCertificateChain[]

		// We set the signing certificate
		parameters.setSigningCertificate(certificateToken);
		// We set the certificate chain
		parameters.setCertificateChain(certificateChain);

		// end::demoCertificateChain[]

		// tag::demoSigningDate[]

		// Set the date of the signature.
		parameters.bLevel().setSigningDate(new Date());

		// end::demoSigningDate[]

		// tag::demoSignatureLevel[]
		
		// Allows to set a final signature level
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

		// end::demoSignatureLevel[]

		CertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		DSSDocument toSignDocument = new InMemoryDocument("Hello world".getBytes());

		// tag::demoSigningProcessGetDataToSign[]

		// Create XAdES service for signature
		XAdESService service = new XAdESService(commonCertificateVerifier);

		// Get the SignedInfo XML segment that need to be signed.
		ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

		// end::demoSigningProcessGetDataToSign[]

		JKSSignatureToken signingToken = null;
		DSSPrivateKeyEntry privateKey = null;

		// tag::demoSigningProcessSign[]

		DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

		// end::demoSigningProcessSign[]

		// tag::demoSigningProcessSignDocument[]
		DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
		// end::demoSigningProcessSignDocument[]

		// tag::i18n[]
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		// A target Locale must be defined for the validator
		validator.setLocale(Locale.FRENCH); // for French language
		// end::i18n[]

		// tag::validationPolicy[]
		Reports reports = validator.validateDocument(new File("/path/to/validation/policy.xml"));
		// end::validationPolicy[]

	}

	public void demo2() {
		// tag::select-pdf-signature-field[]
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setFieldId("field-id");
		// end::select-pdf-signature-field[]
	}

	public void threeAtomicSteps() {
		XAdESService service = new XAdESService(new CommonCertificateVerifier());
		DSSDocument toSignDocument = new InMemoryDocument("Hello world".getBytes());
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		DigestAlgorithm digestAlgorithm = signatureParameters.getDigestAlgorithm();

		JKSSignatureToken signingToken = null;
		DSSPrivateKeyEntry privateKey = null;

		// tag::threeStepsSign[]

		// step 1: generate ToBeSigned data
		ToBeSigned dataToSign = service.getDataToSign(toSignDocument, signatureParameters);

		// step 2: sign ToBeSigned data using a private key
		SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

		// step 3: sign document using a SignatureValue obtained on the previous step
		DSSDocument signedDocument = service.signDocument(toSignDocument, signatureParameters, signatureValue);

		// end::threeStepsSign[]
	}

	public void fourAtomicSteps() {
		XAdESService service = new XAdESService(new CommonCertificateVerifier());
		DSSDocument toSignDocument = new InMemoryDocument("Hello world".getBytes());
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		DigestAlgorithm digestAlgorithm = signatureParameters.getDigestAlgorithm();

		JKSSignatureToken signingToken = null;
		DSSPrivateKeyEntry privateKey = null;

		// tag::fourStepsSign[]

		// step 1: generate ToBeSigned data
		ToBeSigned dataToSign = service.getDataToSign(toSignDocument, signatureParameters);

		// step 2: compute the digest of the ToBeSigned data
		Digest digest = new Digest(signatureParameters.getDigestAlgorithm(), DSSUtils.digest(signatureParameters.getDigestAlgorithm(), dataToSign.getBytes()));

		// step 3: sign the digested data using a private key
		SignatureValue signatureValue = signingToken.signDigest(digest, privateKey);

		// step 4: sign document using a SignatureValue obtained on the previous step
		DSSDocument signedDocument = service.signDocument(toSignDocument, signatureParameters, signatureValue);

		// end::fourStepsSign[]
	}

	@Test
	public void hashComputation() {
		// tag::hashComputation[]
		// Compute hash on a DSSDocument
		DSSDocument document = new InMemoryDocument("Hello World!".getBytes());
		String base64Sha256HashOfDocument = document.getDigest(DigestAlgorithm.SHA256);

		// Compute hash on a byte array
		byte[] binaries = "Hello World".getBytes();
		byte[] sha256HashOfBinaries = DSSUtils.digest(DigestAlgorithm.SHA256, binaries);
		String base64Sha256HashOfBinaries = Utils.toBase64(sha256HashOfBinaries);
		// end::hashComputation[]

		assertEquals(base64Sha256HashOfDocument, base64Sha256HashOfDocument);
	}

}
