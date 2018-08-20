package eu.europa.esig.dss.x509;

import java.util.List;

/**
 * This class allows to inject alternative urls to collect revocation data. This
 * is mainly used to collect revocations from discovered urls in the trusted
 * lists (supplyPoint).
 * 
 * @param <T>
 *        a sub-class of {@code RevocationToken}
 */
public class AlternateUrlsSourceAdapter<T extends RevocationToken> implements RevocationSourceAlternateUrlsSupport<T> {

	private static final long serialVersionUID = 3375119421036319160L;

	private final RevocationSourceAlternateUrlsSupport<T> wrappedSource;
	private final List<String> alternateUrls;

	public AlternateUrlsSourceAdapter(RevocationSourceAlternateUrlsSupport<T> source, List<String> alternateUrls) {
		this.wrappedSource = source;
		this.alternateUrls = alternateUrls;
	}

	@Override
	public T getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		return wrappedSource.getRevocationToken(certificateToken, issuerCertificateToken, alternateUrls);
	}

	@Override
	public T getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken, List<String> alternativeUrls) {
		return wrappedSource.getRevocationToken(certificateToken, issuerCertificateToken, alternativeUrls);
	}

}
