package eu.europa.esig.dss.ws.converter;

import java.util.LinkedList;
import java.util.List;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
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
		if (remoteCertificate == null || Utils.isArrayEmpty(remoteCertificate.getEncodedCertificate())) {
			return null;
		}
		return DSSUtils.loadCertificate(remoteCertificate.getEncodedCertificate());
	}

	/**
	 * Converts the given {@code certificate} to a {@code RemoteCertificate}
	 * @param certificate {@link CertificateToken} to convert
	 * @return {@link RemoteCertificate}
	 */
	public static RemoteCertificate toRemoteCertificate(CertificateToken certificate) {
		if (certificate == null) {
			return null;
		}
		return new RemoteCertificate(certificate.getEncoded());
	}
	
	public static List<CertificateToken> toCertificateTokens(List<RemoteCertificate> remoteCertificates) {
		if (Utils.isCollectionNotEmpty(remoteCertificates)) {
			List<CertificateToken> certificateTokens = new LinkedList<CertificateToken>();
			for (RemoteCertificate remoteCertificate : remoteCertificates) {
				CertificateToken certificateToken = toCertificateToken(remoteCertificate);
				if (certificateToken != null) {
					certificateTokens.add(certificateToken);
				}
			}
			return certificateTokens;
		}
		return null;
	}

}
