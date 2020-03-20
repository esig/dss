package eu.europa.esig.dss.service.http.commons.strategy;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.apache.http.conn.ssl.TrustStrategy;


/**
 * The strategy trusts all certificates by SSL-connection
 * NOTE: please be responsible in the usage of the class! It allows not trusted HTTPS connections.
 *
 */
public class AcceptAllTrustStrategy implements TrustStrategy {

	@Override
	public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		// trust all
		return true;
	}

}
