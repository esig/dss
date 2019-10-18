package eu.europa.esig.dss.spi.x509.revocation;

import java.util.List;
import java.util.Objects;

import eu.europa.esig.dss.model.x509.CertificateToken;

public class CompositeRevocationSource<T extends RevocationToken> implements RevocationSource<T> {

	private static final long serialVersionUID = 8870377682436878544L;

	private final List<RevocationSource<T>> revocationSources;

	public CompositeRevocationSource(List<RevocationSource<T>> revocationSources) {
		Objects.requireNonNull(revocationSources, "RevocationSources is null");
		this.revocationSources = revocationSources;
	}

	@Override
	public T getRevocationToken(final CertificateToken certificateToken, final CertificateToken issuerCertificateToken) {
		for (RevocationSource<T> revocationSource : revocationSources) {
			T revocationToken = revocationSource.getRevocationToken(certificateToken, issuerCertificateToken);
			if (revocationToken != null) {
				return revocationToken;
			}
		}
		return null;
	}

}
