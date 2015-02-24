package eu.europa.ec.markt.dss.cookbook.example.sign;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.cookbook.example.Cookbook;
import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.xades.XAdESService;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;

/**
 * How to set explicit policy.
 */
public class SignXmlXadesBExplicitPolicy extends Cookbook {

	public static void main(String[] args) throws IOException {

		prepareXmlDoc();

		SignatureParameters parameters = new SignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		parameters.setPrivateKeyEntry(privateKey);

		BLevelParameters bLevelParameters = parameters.bLevel();

		//Get and use the explicit policy
		String signaturePolicyId = "http://www.example.com/policy.txt";
		DigestAlgorithm signaturePolicyHashAlgo = DigestAlgorithm.SHA256;
		String signaturePolicyDescription = "Policy text to digest";
		byte[] signaturePolicyDescriptionBytes = signaturePolicyDescription.getBytes();
		byte[] digestedBytes = DSSUtils.digest(signaturePolicyHashAlgo, signaturePolicyDescriptionBytes);

		BLevelParameters.Policy policy = new BLevelParameters.Policy();
		policy.setId(signaturePolicyId);
		policy.setDigestAlgorithm(signaturePolicyHashAlgo);
		policy.setDigestValue(digestedBytes);

		bLevelParameters.setSignaturePolicy(policy);

		// Create common certificate verifier
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		// Create CAdES xadesService for signature
		XAdESService service = new XAdESService(commonCertificateVerifier);

		// Get the SignedInfo segment that need to be signed.
		byte[] dataToSign = service.getDataToSign(toSignDocument, parameters);

		// This function obtains the signature value for signed information using the
		// private key and specified algorithm
		DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		byte[] signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

		// We invoke the xadesService to sign the document with the signature value obtained in
		// the previous step.
		DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

		InputStream is = new ByteArrayInputStream(signedDocument.getBytes());
		DSSUtils.saveToFile(is, "signedXmlXadesBExplicitPolicy.xml");
	}
}
