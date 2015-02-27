package eu.europa.ec.markt.dss.cookbook.example.sign;

import java.io.IOException;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.cookbook.example.Cookbook;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.token.Pkcs12SignatureToken;
import eu.europa.ec.markt.dss.signature.xades.XAdESService;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;

/**
 * How to sign with XAdES-BASELINE-B
 */
public class SignXmlXadesBWithSelfSignedCertificate extends Cookbook {

	public static void main(String[] args) throws IOException {

		// GET document to be signed -
		// Return DSSDocument toSignDocument
		prepareXmlDoc();

		// Create token connection base on a self sign certificate
		String pkcs12TokenFile = getPathFromResource("/rca.p12");
		signingToken = new Pkcs12SignatureToken("password", pkcs12TokenFile);
		privateKey = signingToken.getKeys().get(0);

		// Preparing parameters for the XAdES signature
		SignatureParameters parameters = new SignatureParameters();
		// We choose the level of the signature (-B, -T, -LT, -LTA).
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
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
		// Create XAdES xadesService for signature
		XAdESService service = new XAdESService(commonCertificateVerifier);

		// Get the SignedInfo XML segment that need to be signed.
		byte[] dataToSign = service.getDataToSign(toSignDocument, parameters);

		// This function obtains the signature value for signed information using the
		// private key and specified algorithm
		DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		byte[] signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

		// We invoke the xadesService to sign the document with the signature value obtained in
		// the previous step.
		DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
		//DSSUtils.copy(signedDocument.openStream(), System.out);
		//signedDocument.save("c:/xml_example-xades-enveloped-b-signed-with-self-signed-certificate.xml");

		DSSUtils.saveToFile(signedDocument.openStream(), "signedXmlXadesB_WithSelfSignedCertificate.xml");
	}
}
