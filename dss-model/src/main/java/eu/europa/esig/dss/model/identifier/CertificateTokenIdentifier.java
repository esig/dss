package eu.europa.esig.dss.model.identifier;

import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * This class is used to obtain a unique id for CertificateToken
 */
public final class CertificateTokenIdentifier extends TokenIdentifier {

	private static final long serialVersionUID = -2313198298281443379L;

	public CertificateTokenIdentifier(CertificateToken certificateToken) {
		super("C-", certificateToken);
	}

}
