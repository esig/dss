/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * This class operates on several {@link CertificateSource} with the composite
 * design pattern.
 */
public class ListCertificateSource implements Serializable {

	private static final long serialVersionUID = -7790810642120721289L;

	/**
	 * A list of certificate sources
	 */
	private List<CertificateSource> sources = new ArrayList<>();
	
	/**
	 * Default constructor
	 */
	public ListCertificateSource() {
		// empty
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
	 * Returns an unmodifiable list of embedded {@code CertificateSource}s
	 * 
	 * @return a list of {@link CertificateSource}s
	 */
	public List<CertificateSource> getSources() {
		return Collections.unmodifiableList(sources);
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

	/**
	 * Returns a set of all containing {@link CertificateSourceEntity}
	 * 
	 * @return set of {@link CertificateSourceEntity}s
	 */
	public Set<CertificateSourceEntity> getAllEntities() {
		Set<CertificateSourceEntity> allEntities = new HashSet<>();
		for (CertificateSource certificateSource : sources) {
			allEntities.addAll(certificateSource.getEntities());
		}
		return allEntities;
	}

	/**
	 * This method checks if the embed sources is empty
	 * 
	 * @return true if no source has been added
	 */
	public boolean isEmpty() {
		return sources.isEmpty();
	}
	
	/**
	 * Checks if the ListCertificateSource contains only trusted CertificateSources
	 * 
	 * @return TRUE if all embedded CertificateSources are trusted, FALSE otherwise
	 */
	public boolean areAllCertSourcesTrusted() {
		for (CertificateSource certificateSource : sources) {
			if (!certificateSource.getCertificateSourceType().isTrusted()) {
				return false;
			}
		}
		return true;
	}

	/**
	 * This method verifies if the current list of certificate sources contains a trusted certificate source
	 *
	 * @return TRUE if the list certificate source contains a trusted certificate source, FALSE otherwise
	 */
	public boolean containsTrustedCertSources() {
		for (CertificateSource certificateSource : sources) {
			if (certificateSource.getCertificateSourceType().isTrusted()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * This method checks in all sources in the given certificate is trusted
	 * 
	 * @param certificateToken the {@link CertificateToken} to be checked
	 * @return true if the certificate is trusted
	 */
	public boolean isTrusted(CertificateToken certificateToken) {
		for (CertificateSource source : sources) {
			if (source.isTrusted(certificateToken)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * This method checks in all sources if all embedded certificate are self-signed
	 * 
	 * @return true if all certificates from all sources are self-signed
	 */
	public boolean isAllSelfSigned() {
		for (CertificateSource certificateSource : sources) {
			if (!certificateSource.isAllSelfSigned()) {
				return false;
			}
		}
		return true;
	}

	/**
	 * This method return the different {@link CertificateSourceType} where the
	 * certificate is found
	 * 
	 * @param certificateToken the {@link CertificateToken} to be find
	 * @return a Set with the different sources
	 */
	public Set<CertificateSourceType> getCertificateSource(CertificateToken certificateToken) {
		Set<CertificateSourceType> result = new HashSet<>();
		for (CertificateSource source : sources) {
			if (source.isKnown(certificateToken)) {
				result.add(source.getCertificateSourceType());
			}
		}
		return result;
	}

	/**
	 * This method returns the found {@link CertificateToken} from all
	 * {@link CertificateSource} for the given {@link PublicKey}.
	 * 
	 * @param publicKey the {@link PublicKey} to find in the sources
	 * @return a Set of found {@link CertificateToken}
	 */
	public Set<CertificateToken> getByPublicKey(PublicKey publicKey) {
		Set<CertificateToken> result = new HashSet<>();
		for (CertificateSource source : sources) {
			result.addAll(source.getByPublicKey(publicKey));
		}
		return result;
	}

	/**
	 * This method returns the found {@link CertificateToken} from all
	 * {@link CertificateSource} for the given subject key identifier (SHA-1 of the
	 * public key).
	 * 
	 * @param ski the subject key identifier to find in the sources
	 * @return a Set of found {@link CertificateToken}
	 */
	public Set<CertificateToken> getBySki(byte[] ski) {
		Set<CertificateToken> result = new HashSet<>();
		for (CertificateSource source : sources) {
			result.addAll(source.getBySki(ski));
		}
		return result;
	}

	/**
	 * This method returns the found {@link CertificateToken} from all
	 * {@link CertificateSource} for the given {@link X500PrincipalHelper}.
	 * 
	 * @param subject the {@link X500PrincipalHelper} to find in the sources
	 * @return a Set of found {@link CertificateToken}
	 */
	public Set<CertificateToken> getBySubject(X500PrincipalHelper subject) {
		Set<CertificateToken> result = new HashSet<>();
		for (CertificateSource source : sources) {
			result.addAll(source.getBySubject(subject));
		}
		return result;
	}

	/**
	 * This method returns the found {@link CertificateToken} from all
	 * {@link CertificateSource} for the given {@link SignerIdentifier}.
	 * 
	 * @param signerIdentifier the {@link SignerIdentifier} to find in the
	 *                              sources
	 * @return a Set of found {@link CertificateToken}
	 */
	public Set<CertificateToken> getByCertificateIdentifier(SignerIdentifier signerIdentifier) {
		Set<CertificateToken> result = new HashSet<>();
		for (CertificateSource source : sources) {
			result.addAll(source.getBySignerIdentifier(signerIdentifier));
		}
		return result;
	}

	/**
	 * This method returns the found {@link CertificateToken} from all
	 * {@link CertificateSource} for the given {@link Digest}.
	 * 
	 * @param digest the {@link Digest} to find in the
	 *                              sources
	 * @return a Set of found {@link CertificateToken}
	 */
	public Set<CertificateToken> getByCertificateDigest(Digest digest) {
		Set<CertificateToken> result = new HashSet<>();
		for (CertificateSource source : sources) {
			result.addAll(source.getByCertificateDigest(digest));
		}
		return result;
	}

	/**
	 * This method returns the found {@link CertificateToken} from all
	 * {@link CertificateSource} for the given {@code certificateRef}.
	 * 
	 * @param certificateRef the {@link CertificateRef} to find in the
	 *                              sources
	 * @return a Set of found {@link CertificateToken}
	 */
	public Set<CertificateToken> findTokensFromRefs(CertificateRef certificateRef) {
		Set<CertificateToken> result = new HashSet<>();
		for (CertificateSource source : sources) {
			result.addAll(source.findTokensFromCertRef(certificateRef));
		}
		return result;
	}

	/**
	 * This method returns the number of set {@link CertificateSource}s
	 * 
	 * @return the number of found {@link CertificateSource}
	 */
	public int getNumberOfSources() {
		return sources.size();
	}

	/**
	 * This method returns the number of found {@link CertificateToken} in all
	 * sources
	 * 
	 * @return the number of found {@link CertificateToken}
	 */
	public int getNumberOfCertificates() {
		return getAllCertificateTokens().size();
	}

	/**
	 * This method returns the number of found {@link CertificateSourceEntity} in
	 * all sources
	 * 
	 * @return the number of found {@link CertificateSourceEntity}
	 */
	public int getNumberOfEntities() {
		return getAllEntities().size();
	}

}
