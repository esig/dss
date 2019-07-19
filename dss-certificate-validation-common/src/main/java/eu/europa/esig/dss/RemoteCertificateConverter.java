package eu.europa.esig.dss;

import eu.europa.esig.dss.x509.CertificateToken;

public class RemoteCertificateConverter {
	
	/**
	 * Converts the given {@code remoteCertificate} to a {@code CertificateToken}
	 * @param remoteCertificate {@link RemoteDocument} to convert
	 * @return {@link CertificateToken}
	 */
	public static CertificateToken toCertificateToken(RemoteCertificate remoteCertificate) {
		return DSSUtils.loadCertificate(remoteCertificate.getEncodedCertificate());
	}

}
