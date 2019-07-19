package eu.europa.esig.dss.ws.converter;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
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

	/**
	 * Converts the given {@code certificate} to a {@code RemoteCertificate}
	 * @param certificate {@link CertificateToken} to convert
	 * @return {@link RemoteCertificate}
	 */
	public static RemoteCertificate toRemoteCertificate(CertificateToken certificate) {
		return new RemoteCertificate(certificate.getEncoded());
	}

}
