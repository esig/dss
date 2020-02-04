package eu.europa.esig.dss.validation;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;

public class ListCertificateSource {
	
	/**
	 * A list of certificate sources
	 */
	private List<CommonCertificateSource> sources = new ArrayList<>();
	
	/**
	 * Default constructor
	 */
	public ListCertificateSource() {
	}
	
	/**
	 * This constructor allows to instantiate on object of the class with one certificateSource
	 * 
	 * @param certificateSource {@link SignatureCertificateSource}
	 */
	public ListCertificateSource(CommonCertificateSource certificateSource) {
		add(certificateSource);
	}
	
	/**
	 * This method allows to add a certificate source to the list
	 * 
	 * @param certificateSource {@link SignatureCertificateSource}
	 */
	public void add(CommonCertificateSource certificateSource) {
		sources.add(certificateSource);
	}
	
	/**
	 * Allows to add a list of embedded certificate sources to the list of certificate sources
	 * 
	 * @param listCertificateSource {@link ListCertificateSource}
	 */
	public void addAll(ListCertificateSource listCertificateSource) {
		addAll(listCertificateSource.getSources());
	}

	/**
	 * Allows to add a list of certificate sources
	 * 
	 * @param certificateSources a list of {@link CommonCertificateSource}s to add
	 */
	public void addAll(List<CommonCertificateSource> certificateSources) {
		sources.addAll(certificateSources);
	}
	
	/**
	 * Returns a list of embedded {@code CommonCertificateSource}s
	 * 
	 * @return a list of {@link CommonCertificateSource}s
	 */
	public List<CommonCertificateSource> getSources() {
		return sources;
	}

	/**
	 * Returns a set of all containing certificate tokens
	 * 
	 * @return set of {@link CertificateToken}s
	 */
	public Set<CertificateToken> getAllCertificateTokens() {
		Set<CertificateToken> allTokens = new HashSet<>();
		for (CommonCertificateSource certificateSource : sources) {
			allTokens.addAll(certificateSource.getCertificates());
		}
		return allTokens;
	}

	/**
	 * Returns a {@code CertificateToken} by its given digest
	 * 
	 * @param certDigest {@link Digest} to find a certificate token with
	 * @return {@link CertificateToken}
	 */
	public CertificateToken getCertificateTokenByDigest(Digest certDigest) {
		for (CommonCertificateSource certificateSource : sources) {
			CertificateToken certificateToken = certificateSource.getCertificateTokenByDigest(certDigest);
			if (certificateToken != null) {
				return certificateToken;
			}
		}
		return null;
	}

}
