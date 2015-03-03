package eu.europa.ec.markt.dss.cookbook.example.sign;

import java.io.IOException;
import java.util.Date;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.cookbook.sources.JavaKeyStoreTool;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.token.JKSSignatureToken;
import eu.europa.ec.markt.dss.signature.token.KSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.xades.XAdESService;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;

public class SigningApplication {

	public static void main(String[] args) throws IOException {

		//GET THE LOCATION OF YOUR JKS FILE
		String location = "yourFile.jks";
		JavaKeyStoreTool jks = new JavaKeyStoreTool(location, "password");

		JKSSignatureToken signingToken = new JKSSignatureToken(location, "password");

		KSPrivateKeyEntry privateKey = jks.getPrivateKey("dss", "password");

		DSSDocument toBeSigned = new FileDocument("src/test/resources/xml_example.xml");

		SignatureParameters params = new SignatureParameters();

		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(privateKey.getCertificate());
		params.setCertificateChain(privateKey.getCertificateChain());
		params.bLevel().setSigningDate(new Date());

		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(commonCertificateVerifier);
		byte[] dataToSign = service.getDataToSign(toBeSigned, params);
		byte[] signatureValue = signingToken.sign(dataToSign, params.getDigestAlgorithm(), privateKey);
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);
		DSSUtils.copy(signedDocument.openStream(), System.out);
	}
}
