package eu.europa.esig.dss.pades;

import java.awt.Font;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore.PasswordProtection;
import java.util.List;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.MSCAPISignatureToken;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

public class InternationalPilot {

	public static void main(String[] args) throws IOException {

		DSSDocument doc = new FileDocument("src/test/resources/test_signed_agreement.pdf");

		Pkcs12SignatureToken johnToken = new Pkcs12SignatureToken(new File("src/test/resources/john_doe.p12"),
				new PasswordProtection("password".toCharArray()));
		
		List<DSSPrivateKeyEntry> johnKeys = johnToken.getKeys();
		DSSPrivateKeyEntry johnKey = johnKeys.iterator().next();
		
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		PAdESService service = new PAdESService(certificateVerifier);
		

		PAdESSignatureParameters parameters = new PAdESSignatureParameters();
		parameters.setSigningCertificate(johnKey.getCertificate());
		parameters.setCertificateChain(johnKey.getCertificateChain());
		parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		SignatureImageParameters signatureImageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setFont(new DSSJavaFont(Font.SANS_SERIF));
		textParameters.setText("Digitally signed by:\n" + DSSASN1Utils.getHumanReadableName(johnKey.getCertificate()));
		signatureImageParameters.setTextParameters(textParameters);
		signatureImageParameters.setxAxis(300);
		signatureImageParameters.setyAxis(650);

		parameters.setImageParameters(signatureImageParameters);

		ToBeSigned dataToSign = service.getDataToSign(doc, parameters);
		SignatureValue signatureValue = johnToken.sign(dataToSign, parameters.getDigestAlgorithm(), johnKey);
		DSSDocument signedByJohn = service.signDocument(doc, parameters, signatureValue);

//		signedByJohn.save("target/signedJohn.pdf");

		MSCAPISignatureToken mscapi = new MSCAPISignatureToken();

		List<DSSPrivateKeyEntry> keys = mscapi.getKeys();
		DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(1);

		certificateVerifier = new CommonCertificateVerifier();
		service = new PAdESService(certificateVerifier);

		parameters = new PAdESSignatureParameters();
		parameters.setSigningCertificate(dssPrivateKeyEntry.getCertificate());
		parameters.setCertificateChain(dssPrivateKeyEntry.getCertificateChain());
		parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		signatureImageParameters = new SignatureImageParameters();
		textParameters = new SignatureImageTextParameters();
		textParameters.setFont(new DSSJavaFont(Font.SANS_SERIF));
		textParameters.setText("Digitally signed by:\nPierrick Vandenbroucke");
		signatureImageParameters.setTextParameters(textParameters);
		signatureImageParameters.setxAxis(430);
		signatureImageParameters.setyAxis(650);

		parameters.setImageParameters(signatureImageParameters);

		dataToSign = service.getDataToSign(signedByJohn, parameters);
		signatureValue = mscapi.sign(dataToSign, parameters.getDigestAlgorithm(), dssPrivateKeyEntry);
		DSSDocument signedByJohnAndQES = service.signDocument(signedByJohn, parameters, signatureValue);

		signedByJohnAndQES.save("target/signedJohnQES.pdf");

	}

}
