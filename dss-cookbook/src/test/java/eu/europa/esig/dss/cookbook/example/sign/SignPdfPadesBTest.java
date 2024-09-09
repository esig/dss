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
package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdfa.PDFAValidationResult;
import eu.europa.esig.dss.pdfa.validation.PDFADocumentValidator;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * How to sign PDF Document with PAdES-BASELINE-B
 */
class SignPdfPadesBTest extends CookbookTools {

	@Test
	void signPAdESBaselineB() throws Exception {

		// GET document to be signed -
		// Return DSSDocument toSignDocument
		preparePdfDoc();

		// Get a token connection based on a pkcs12 file commonly used to store private
		// keys with accompanying public key certificates, protected with a password-based
		// symmetric key -
		// Return AbstractSignatureTokenConnection signingToken

		// and it's first private key entry from the PKCS12 store
		// Return DSSPrivateKeyEntry privateKey *****

		try (SignatureTokenConnection signingToken = getPkcs12Token()) {
			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

			// tag::demo[]
			// import eu.europa.esig.dss.pades.PAdESSignatureParameters;
			// import eu.europa.esig.dss.enumerations.SignatureLevel;
			// import eu.europa.esig.dss.enumerations.DigestAlgorithm;
			// import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
			// import eu.europa.esig.dss.pades.signature.PAdESService;
			// import eu.europa.esig.dss.model.ToBeSigned;
			// import eu.europa.esig.dss.model.SignatureValue;
			// import eu.europa.esig.dss.model.DSSDocument;

			// Preparing parameters for the PAdES signature
			PAdESSignatureParameters parameters = new PAdESSignatureParameters();
			// We choose the level of the signature (-B, -T, -LT, -LTA).
			parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
			// We set the digest algorithm to use with the signature algorithm. You must use the
			// same parameter when you invoke the method sign on the token. The default value is
			// SHA256
			parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

			// We set the signing certificate
			parameters.setSigningCertificate(privateKey.getCertificate());
			// We set the certificate chain
			parameters.setCertificateChain(privateKey.getCertificateChain());

			// Create common certificate verifier
			CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
			// Create PAdESService for signature
			PAdESService service = new PAdESService(commonCertificateVerifier);

			// Get the SignedInfo segment that need to be signed.
			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

			// This function obtains the signature value for signed information using the
			// private key and specified algorithm
			DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
			SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

			// Optionally or for debug purpose :
			// Validate the signature value against the original dataToSign
			assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, privateKey.getCertificate()));

			// We invoke the padesService to sign the document with the signature value obtained in
			// the previous step.
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

			// end::demo[]

			// tag::policy[]
			// import eu.europa.esig.dss.model.Policy;
			// import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
			// import eu.europa.esig.dss.enumerations.DigestAlgorithm;

			// Instantiate a Policy object
			Policy signaturePolicy = new Policy();
			// The string representation of the OID of the signature policy to use when signing.
			signaturePolicy.setId("1.2.3.4.5.6");
			// Defines a policy identifier qualifier
			signaturePolicy.setQualifier(ObjectIdentifierQualifier.OID_AS_URN);
			// Defines a description for a signature policy
			signaturePolicy.setDescription("Perfect Signature Policy");
			// The hash function used to compute the value of the SignaturePolicyHashValue entry. 
			// Entries must be represented the same way as in table 257 of ISO 32000-1 (cf. <<R05>>).
			signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA1);
			// The value of the hash of the signature policy, computed the same way as 
			// in clause 5.2.9 of CAdES (ETSI EN 319 122 (cf. <<R02>>)).
			signaturePolicy.setDigestValue(new byte[] { 'd', 'i', 'g', 'e', 's', 't', 'v', 'a', 'l', 'u', 'e' });
			// Defines a URI where the policy can be accessed from
			signaturePolicy.setSpuri("http://spuri.test");
			parameters.bLevel().setSignaturePolicy(signaturePolicy);
			// end::policy[]

			// tag::docmdp[]
			// import eu.europa.esig.dss.enumerations.CertificationPermission;

			// Set the certification signature dictionary
			parameters.setPermission(CertificationPermission.NO_CHANGE_PERMITTED);
			// end::docmdp[]

			testFinalDocument(signedDocument);

			final DSSDocument pdfDocument = signedDocument;

			// tag::pdfa[]
			// import eu.europa.esig.dss.pdfa.PDFAValidationResult;
			// import eu.europa.esig.dss.pdfa.validation.PDFADocumentValidator;
			// import eu.europa.esig.dss.validation.reports.Reports;
			// import eu.europa.esig.dss.diagnostic.DiagnosticData;
			// import java.util.Collection;

			// Create a PDFADocumentValidator to perform validation against PDF/A specification
			PDFADocumentValidator documentValidator = new PDFADocumentValidator(pdfDocument);

			// Extract PDF/A validation result
			// This report contains only validation of a document against PDF/A specification
			// and no signature validation process result
			PDFAValidationResult pdfaValidationResult = documentValidator.getPdfaValidationResult();

			// This variable contains the name of the identified PDF/A profile
			// (or closest if validation failed)
			String profileId = pdfaValidationResult.getProfileId();

			// Checks whether the PDF document is compliant to the identified PDF profile
			boolean compliant = pdfaValidationResult.isCompliant();

			// Returns the error messages occurred during the PDF/A verification
			Collection<String> errorMessages = pdfaValidationResult.getErrorMessages();

			// It is also possible to perform the signature validation process and
			// extract the PDF/A validation result from DiagnosticData

			// Configure PDF/A document validator and perform validation of the document
			documentValidator.setCertificateVerifier(commonCertificateVerifier);
			Reports reports = documentValidator.validateDocument();

			// Extract the interested information from DiagnosticData
			DiagnosticData diagnosticData = reports.getDiagnosticData();
			profileId = diagnosticData.getPDFAProfileId();
			compliant = diagnosticData.isPDFACompliant();
			errorMessages = diagnosticData.getPDFAValidationErrors();
			// end::pdfa[]

			assertNotNull(profileId);
			assertFalse(compliant);
			assertTrue(Utils.isCollectionNotEmpty(errorMessages));
		}
	}
}
