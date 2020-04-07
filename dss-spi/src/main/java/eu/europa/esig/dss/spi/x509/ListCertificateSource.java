package eu.europa.esig.dss.spi.x509;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;

public class ListCertificateSource {
	
	/**
	 * A list of certificate sources
	 */
	private List<CertificateSource> sources = new ArrayList<>();
	
	/**
	 * Default constructor
	 */
	public ListCertificateSource() {
	}
	
	/**
	 * This constructor allows to instantiate an object of the class with one
	 * {@code CertificateSource}
	 * 
	 * @param certificateSource {@link CertificateSource}
	 */
	public ListCertificateSource(CertificateSource certificateSource) {
		add(certificateSource);
	}

	/**
	 * This constructor allows to instantiate an object of the class with a list of
	 * {@code CertificateSource}
	 * 
	 * @param certificateSources a list of {@link CertificateSource}
	 */
	public ListCertificateSource(List<CertificateSource> certificateSources) {
		addAll(certificateSources);
	}

	/**
	 * Allows to add a list of embedded certificate sources to the list of certificate sources
	 * 
	 * @param listCertificateSource {@link ListCertificateSource}
	 */
	public void addAll(ListCertificateSource listCertificateSource) {
		if (listCertificateSource != null) {
			addAll(listCertificateSource.getSources());
		}
	}

	/**
	 * Allows to add a list of certificate sources
	 * 
	 * @param certificateSources a list of {@link CertificateSource}s to add
	 */
	public void addAll(List<CertificateSource> certificateSources) {
		if (certificateSources != null) {
			for (CertificateSource certificateSource : certificateSources) {
				add(certificateSource);
			}
		}
	}
	
	/**
	 * This method allows to add a certificate source to the list
	 * 
	 * @param certificateSource {@link CertificateSource}
	 */
	public void add(CertificateSource certificateSource) {
		if (certificateSource != null) {
			sources.add(certificateSource);
		}
	}

	/**
	 * Returns a list of embedded {@code CertificateSource}s
	 * 
	 * @return a list of {@link CertificateSource}s
	 */
	public List<CertificateSource> getSources() {
		return sources;
	}

	/**
	 * Returns a set of all containing certificate tokens
	 * 
	 * @return set of {@link CertificateToken}s
	 */
	public Set<CertificateToken> getAllCertificateTokens() {
		Set<CertificateToken> allTokens = new HashSet<>();
		for (CertificateSource certificateSource : sources) {
			allTokens.addAll(certificateSource.getCertificates());
		}
		return allTokens;
	}

	public Set<CertificateSourceEntity> getAllEntities() {
		Set<CertificateSourceEntity> allEntities = new HashSet<>();
		for (CertificateSource certificateSource : sources) {
			allEntities.addAll(certificateSource.getEntities());
		}
		return allEntities;
	}

	public boolean isEmpty() {
		return sources.isEmpty();
	}

	public boolean isTrusted(CertificateToken certificateToken) {
		for (CertificateSource source : sources) {
			if (source.isTrusted(certificateToken)) {
				return true;
			}
		}
		return false;
	}

	public Set<CertificateSourceType> getCertificateSource(CertificateToken certificateToken) {
		Set<CertificateSourceType> result = new HashSet<>();
		for (CertificateSource source : sources) {
			if (source.isKnown(certificateToken)) {
				result.add(source.getCertificateSourceType());
			}
		}
		return result;
	}

	public Set<CertificateToken> getByPublicKey(PublicKey publicKey) {
		Set<CertificateToken> result = new HashSet<>();
		for (CertificateSource source : sources) {
			result.addAll(source.getByPublicKey(publicKey));
		}
		return result;
	}

	public Set<CertificateToken> getBySki(byte[] ski) {
		Set<CertificateToken> result = new HashSet<>();
		for (CertificateSource source : sources) {
			result.addAll(source.getBySki(ski));
		}
		return result;
	}

	public Set<CertificateToken> getBySubject(X500PrincipalHelper subject) {
		Set<CertificateToken> result = new HashSet<>();
		for (CertificateSource source : sources) {
			result.addAll(source.getBySubject(subject));
		}
		return result;
	}

	public Set<CertificateToken> getByCertificateIdentifier(CertificateIdentifier certificateIdentifier) {
		Set<CertificateToken> result = new HashSet<>();
		for (CertificateSource source : sources) {
			result.addAll(source.getByCertificateIdentifier(certificateIdentifier));
		}
		return result;
	}

	public int getNumberOfCertificates() {
		return getAllCertificateTokens().size();
	}

	public int getNumberOfEntities() {
		return getAllEntities().size();
	}

}
