package eu.europa.esig.dss.applet;

import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.tsl.KeyUsageBit;
import eu.europa.esig.dss.x509.CertificateToken;

public class CertificateRetriever {

	private static final Logger logger = LoggerFactory.getLogger(CertificateRetriever.class);

	private static final String ADD_CERTIFICATE = "addCertificate";
	private static final String ADD_CERTIFICATE_CHAIN = "addCertificateChain";

	private SignatureTokenConnection tokenConnection;
	private JSInvoker jsInvoker;

	public CertificateRetriever(SignatureTokenConnection tokenConnection, JSInvoker jsInvoker) {
		this.tokenConnection = tokenConnection;
		this.jsInvoker = jsInvoker;
	}

	public void injectCertificates() {
		List<DSSPrivateKeyEntry> keys = tokenConnection.getKeys();
		if ((keys != null) && (keys.size() > 0)) {
			for (DSSPrivateKeyEntry dssPrivateKeyEntry : keys) {

				CertificateToken certificate = dssPrivateKeyEntry.getCertificate();

				String base64Certificate = certificate.getBase64Encoded();
				String readableCertificate = certificate.getReadableCertificate();

				StringBuffer tooltip = new StringBuffer();
				Set<KeyUsageBit> keyUsageBits = certificate.getKeyUsageBits();
				if (keyUsageBits != null) {
					tooltip.append("Key usage(s) : ");
					tooltip.append(keyUsageBits);
				}

				logger.info("Certificate found : " + readableCertificate);
				try {
					jsInvoker.injectCertificate(ADD_CERTIFICATE, base64Certificate, readableCertificate, dssPrivateKeyEntry.getEncryptionAlgorithm().name(), tooltip.toString());
				} catch (Exception e) {
					logger.error("Unable to inject the certificate : " + e.getMessage(), e);
				}

				CertificateToken[] certificateChain = dssPrivateKeyEntry.getCertificateChain();
				if ((certificateChain != null) && (certificateChain.length > 0)) {
					for (CertificateToken token : certificateChain) {
						try {
							jsInvoker.injectCertificateChain(ADD_CERTIFICATE_CHAIN, base64Certificate, token.getBase64Encoded());
						} catch (Exception e) {
							logger.error("Unable to inject the certificate : " + e.getMessage(), e);
						}
					}
				}

			}
		}
	}

}
