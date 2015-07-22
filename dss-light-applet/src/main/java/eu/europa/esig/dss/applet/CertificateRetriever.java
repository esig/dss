package eu.europa.esig.dss.applet;

import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.x509.CertificateToken;

public class CertificateRetriever {

	private static final Logger logger = LoggerFactory.getLogger(CertificateRetriever.class);

	private static final String ADD_CERTIFICATE = "addCertificate";

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

				String base64Certificate = DatatypeConverter.printBase64Binary(certificate.getEncoded());

				String readableCertificate = certificate.getSubjectDN().getName();
				final int dnStartIndex = readableCertificate.indexOf("CN=") + 3;
				if ((dnStartIndex > 0) && (readableCertificate.indexOf(",", dnStartIndex) > 0)) {
					readableCertificate = readableCertificate.substring(dnStartIndex, readableCertificate.indexOf(",", dnStartIndex)) + " (SN:" + certificate.getSerialNumber()
							+ ")";
				}

				logger.info("Certificate found : " + readableCertificate);
				try {
					jsInvoker.injectCertificate(ADD_CERTIFICATE, base64Certificate, readableCertificate);
				} catch (Exception e) {
					logger.error("Unable to inject the certificate : " + e.getMessage(), e);
				}
			}
		}
	}

}
