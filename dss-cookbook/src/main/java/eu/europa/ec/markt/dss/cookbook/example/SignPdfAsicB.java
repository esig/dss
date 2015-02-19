package eu.europa.ec.markt.dss.cookbook.example;

import java.io.IOException;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.asic.ASiCService;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;

/**
 * How to sign with ASiC-BASELINE-B
 */
public class SignPdfAsicB extends Cookbook {

	public static void main(String[] args) throws IOException {

		// GET document to be signed - 
		// Return DSSDocument toSignDocument
		preparePdfDoc();
		
		// Get a token connection based on a pkcs12 file commonly used to store private
		// keys with accompanying public key certificates, protected with a password-based
		// symmetric key - 
		// Return AbstractSignatureTokenConnection signingToken 
		
		// and he first private key entry from the PKCS12 store
		// Return DSSPrivateKeyEntry privateKey *****
		preparePKCS12TokenAndKey();


		// Preparing parameters for the AsicS signature
		SignatureParameters parameters = new SignatureParameters();
		// We choose the level of the signature (-B, -T, -LT).
		parameters.setSignatureLevel(SignatureLevel.ASiC_S_BASELINE_B);
		// We choose the type of the signature packaging (ENVELOPED, ENVELOPING, DETACHED).
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		// We set the digest algorithm to use with the signature algorithm. You must use the
		// same parameter when you invoke the method sign on the token. The default value is
		// SHA256
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		// We choose the private key with the certificate and corresponding certificate
		// chain.
		parameters.setPrivateKeyEntry(privateKey);
		
		
		// Create common certificate verifier
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		// Create ASiCS service for signature
		ASiCService service = new ASiCService(commonCertificateVerifier);

		// Get the SignedInfo segment that need to be signed.
		byte[] dataToSign = service.getDataToSign(toSignDocument, parameters);

		// This function obtains the signature value for signed information using the
		// private key and specified algorithm
		final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		byte[] signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

		// We invoke the xadesService to sign the document with the signature value obtained in
		// the previous step.
		DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
		//signedDocument.save("c:/xml_example-asic-b-signed.asic");
		//DSSUtils.copy(signedDocument.openStream(), System.out);
		DSSUtils.saveToFile(signedDocument.openStream(), "signedPdfAsicB");
	}
}
