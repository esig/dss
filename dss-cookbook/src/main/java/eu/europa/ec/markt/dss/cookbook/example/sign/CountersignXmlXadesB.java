package eu.europa.ec.markt.dss.cookbook.example.sign;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.cookbook.example.Cookbook;
import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.parameter.BLevelParameters.SignerLocation;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.xades.XAdESService;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;

/**
 * How to generate a countersignature over an existing signature
 */
public class CountersignXmlXadesB extends Cookbook {

	public static void main(final String[] args) throws IOException {

		//Select a document to countersign
		DSSDocument toCountersignDocument = new FileDocument("signedXmlXadesB.xml");

		// Create a token connection based on a pkcs12 file
		preparePKCS12TokenAndKey();

		// Preparing the parameters for the countersignature
		SignatureParameters countersigningParameters = new SignatureParameters();
		countersigningParameters.setSigningToken(signingToken);
		countersigningParameters.setPrivateKeyEntry(privateKey);
		countersigningParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		countersigningParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		//The ID of the signature was manually retrieved in the document to countersign
		countersigningParameters.setToCounterSignSignatureId("id-E2727C1693F3602F89D515E6BEE5F1DC");

		//Possibility to add properties in the countersignature
		BLevelParameters blParam = countersigningParameters.bLevel();
		SignerLocation location = new SignerLocation();
		location.setCountry("Belgium");
		location.setStateOrProvince("Luxembourg");
		blParam.setSignerLocation(location);

		// Countersign the document
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(commonCertificateVerifier);
		DSSDocument countersignedDocument = service.counterSignDocument(toCountersignDocument, countersigningParameters);

		InputStream is = new ByteArrayInputStream(countersignedDocument.getBytes());
		DSSUtils.saveToFile(is, "countersigned.xml");
	}
}
