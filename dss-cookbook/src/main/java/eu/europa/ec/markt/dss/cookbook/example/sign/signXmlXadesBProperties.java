package eu.europa.ec.markt.dss.cookbook.example.sign;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.cookbook.example.Cookbook;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.xades.XAdESService;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;

/**
 * How to add signed properties to the signature.
 */
public class signXmlXadesBProperties extends Cookbook {

	public static void main(String[] args) throws DSSException, IOException {

		prepareXmlDoc();

		preparePKCS12TokenAndKey();

		SignatureParameters parameters = new SignatureParameters();
		parameters.setPrivateKeyEntry(privateKey);
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA512);

		BLevelParameters bLevelParameters = parameters.bLevel();
		bLevelParameters.addClaimedSignerRole("My Claimed Role");

		BLevelParameters.SignerLocation signerLocation = new BLevelParameters.SignerLocation();
		signerLocation.setCountry("Belgium");
		signerLocation.setStateOrProvince("Luxembourg");
		signerLocation.setPostalCode("1234");
		signerLocation.setCity("SimCity");
		bLevelParameters.setSignerLocation(signerLocation);

		List<String> commitmentTypeIndications = new ArrayList<String>();
		commitmentTypeIndications.add("http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin");
		commitmentTypeIndications.add("http://uri.etsi.org/01903/v1.2.2#ProofOfApproval");
		bLevelParameters.setCommitmentTypeIndications(commitmentTypeIndications);

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(verifier);
		byte[] dataToSign = service.getDataToSign(toSignDocument, parameters);
		byte[] signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);

		DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

		DSSUtils.saveToFile(signedDocument.openStream(), "signedXmlXadesBProperties.xml");
	}
}
