package eu.europa.esig.dss.x509;

import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import eu.europa.esig.dss.DSSException;

public class BCTokenBuilder {

	private static BouncyCastleProvider provider;

	public BCTokenBuilder() {
		if(provider == null) {
			provider = new BouncyCastleProvider();
			Security.addProvider(provider);
		}
	}

	public CertificateToken buildCertificateToken(InputStream in) {
		try {
			CertificateFactory factory = CertificateFactory.getInstance("X509", "BC");
			X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
			return new CertificateToken(cert);
		} catch (Exception e) {
			throw new DSSException(e);
		}

	}

}
