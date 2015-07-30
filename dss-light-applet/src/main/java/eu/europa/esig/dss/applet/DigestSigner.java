package eu.europa.esig.dss.applet;

import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.x509.CertificateToken;

public class DigestSigner {

	private static final Logger logger = LoggerFactory.getLogger(DigestSigner.class);

	private static final String ADD_SIGNATURE = "addSignature";

	private SignatureTokenConnection tokenConnection;
	private ToBeSigned toBeSigned;
	private DigestAlgorithm digestAlgorithm;
	private String base64SignerCertificate;
	private JSInvoker jsInvoker;

	public DigestSigner(SignatureTokenConnection tokenConnection, ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, String base64SignerCertificate, JSInvoker jsInvoker) {
		this.tokenConnection = tokenConnection;
		this.toBeSigned = toBeSigned;
		this.digestAlgorithm = digestAlgorithm;
		this.base64SignerCertificate = base64SignerCertificate;
		this.jsInvoker = jsInvoker;
	}

	public void signAndInject() {
		logger.info("Looking for certificate ...");
		DSSPrivateKeyEntry signerKeyEntry = retrieveSignerCertificate();
		if (signerKeyEntry != null) {
			logger.info("Certificate found");
			logger.info("Starting to sign digest...");
			SignatureValue signatureValue = tokenConnection.sign(toBeSigned, digestAlgorithm, signerKeyEntry);
			logger.info("Digest signature is finished.");
			try {
				jsInvoker.injectSignature(ADD_SIGNATURE, DatatypeConverter.printBase64Binary(signatureValue.getValue()));
			} catch (Exception e) {
				logger.error("Unable to inject the signature : " + e.getMessage(), e);
			}
		} else {
			logger.error("Unable to retrieve the signer certificate from the token : " + base64SignerCertificate);
		}

	}

	private DSSPrivateKeyEntry retrieveSignerCertificate() {
		DSSPrivateKeyEntry signerKeyEntry = null;
		List<DSSPrivateKeyEntry> keys = tokenConnection.getKeys();
		if (keys != null) {
			for (DSSPrivateKeyEntry entry : keys) {
				CertificateToken certificate = entry.getCertificate();
				String base64Certificate = DatatypeConverter.printBase64Binary(certificate.getEncoded());
				if (base64Certificate.equals(base64SignerCertificate)) {
					signerKeyEntry = entry;
				}
				break;
			}
		}
		return signerKeyEntry;
	}

}
