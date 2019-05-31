package eu.europa.esig.dss.cookbook.example.snippets;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.JKSSignatureToken;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class Snippets {

	@SuppressWarnings({ "null", "unused" })
	public void demo() {

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		CertificateToken certificateToken = new CertificateToken(null);
		List<CertificateToken> certificateChain = new LinkedList<CertificateToken>();

		// tag::demoCertificateChain[]

		// We set the signing certificate
		parameters.setSigningCertificate(certificateToken);
		// We set the certificate chain
		parameters.setCertificateChain(certificateChain);

		// end::demoCertificateChain[]

		// tag::demoSigningDate[]

		// We set the date of the signature.
		parameters.bLevel().setSigningDate(new Date());

		// end::demoSigningDate[]

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

	}

}
