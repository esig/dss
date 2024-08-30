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
import eu.europa.esig.dss.model.identifier.EntityIdentifier;
import eu.europa.esig.dss.model.identifier.KeyIdentifier;
import eu.europa.esig.dss.model.identifier.X500NameIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * This class is the common class for all {@code CertificateSource}. It stores
 * added certificates and allows to retrieve them with several methods
 */
public class CommonCertificateSource implements CertificateSource {

	private static final long serialVersionUID = -5031898106342793626L;

	private static final Logger LOG = LoggerFactory.getLogger(CommonCertificateSource.class);
	
	/**
	 * This object is used to match {@code CertificateToken}s and {@code CertificateRef}s
	 */
	protected final transient CertificateTokenRefMatcher certificateMatcher = new CertificateTokenRefMatcher();

	/**
	 * Map of entries, the key is a hash of the entity key (public key + subject name combination).
	 * All entries share the same key pair and a subject name.
	 */
	private Map<EntityIdentifier, EquivalentCertificatesEntity> entitiesByEntityKey = new HashMap<>();

	/**
	 * Map of entries, the key is a hash of a public key.
	 * For a same KeyIdentifier, different subject names (and certificates) are possible.
	 */
	private Map<KeyIdentifier, EquivalentCertificatesEntity> entitiesByPublicKey = new HashMap<>();

	/**
	 * Map of tokens, the key is a key of X500Name (RDN)
	 * For a same SubjectX500Principal, different key pairs (and certificates) are possible
	 */
	private Map<X500NameIdentifier, Set<CertificateToken>> tokensBySubject = new HashMap<>();

	/**
	 * The default constructor
	 */
	public CommonCertificateSource() {
		// empty
	}

	/**
	 * This method adds an external certificate to the source. If the public is
	 * already known, the certificate is merged in the
	 * {@code CertificateSourceEntity}
	 *
	 * @param certificateToAdd the certificate to be added
	 * @return the corresponding certificate token
	 */
	@Override
	public CertificateToken addCertificate(final CertificateToken certificateToAdd) {
		Objects.requireNonNull(certificateToAdd, "The certificate must be filled");

		if (LOG.isTraceEnabled()) {
			LOG.trace("Certificate to add: {} | {}", certificateToAdd.getIssuerX500Principal(), certificateToAdd.getSerialNumber());
		}

		synchronized (entitiesByEntityKey) {
			final EntityIdentifier entityKey = certificateToAdd.getEntityKey();
			EquivalentCertificatesEntity poolEntity = entitiesByEntityKey.get(entityKey);
			if (poolEntity == null) {
				LOG.trace("Entity key {} is not in the pool", entityKey);
				poolEntity = new EquivalentCertificatesEntity(certificateToAdd);
				entitiesByEntityKey.put(entityKey, poolEntity);
			} else {
				LOG.trace("Entity key {} is already in the pool", entityKey);
				poolEntity.addEquivalentCertificate(certificateToAdd);
			}
		}

		synchronized (entitiesByPublicKey) {
			final KeyIdentifier keyIdentifier = new KeyIdentifier(certificateToAdd.getPublicKey());
			EquivalentCertificatesEntity poolEntity = entitiesByPublicKey.get(keyIdentifier);
			if (poolEntity == null) {
				LOG.trace("Key identifier {} is not in the pool", keyIdentifier);
				poolEntity = new EquivalentCertificatesEntity(certificateToAdd);
				entitiesByPublicKey.put(keyIdentifier, poolEntity);
			} else {
				LOG.trace("Key identifier {} is already in the pool", keyIdentifier);
				poolEntity.addEquivalentCertificate(certificateToAdd);
			}
		}

		synchronized (tokensBySubject) {
			X500NameIdentifier x500NameIdentifier = new X500NameIdentifier(certificateToAdd.getSubject().getPrincipal());
			tokensBySubject.computeIfAbsent(x500NameIdentifier, k -> new HashSet<>()).add(certificateToAdd);
		}

		return certificateToAdd;
	}

	/**
	 * This method removes the corresponding certificate token from the certificate source
	 *
	 * @param certificateToRemove {@link CertificateToken} to remove
	 */
	protected void removeCertificate(final CertificateToken certificateToRemove) {
		Objects.requireNonNull(certificateToRemove, "The certificate must be filled");

		if (LOG.isTraceEnabled()) {
			LOG.trace("Certificate to remove: {} | {}", certificateToRemove.getIssuerX500Principal(), certificateToRemove.getSerialNumber());
		}

		synchronized (entitiesByEntityKey) {
			final EntityIdentifier entityKey = certificateToRemove.getEntityKey();
			EquivalentCertificatesEntity poolEntity = entitiesByEntityKey.get(entityKey);
			if (poolEntity == null) {
				LOG.trace("Entity key {} is not in the pool", entityKey);
			} else {
				LOG.trace("Entity key {} is in the pool", entityKey);
				if (poolEntity.getEquivalentCertificates().size() == 1) {
					LOG.trace("Remove the entity key {} from the pool", entityKey);
					entitiesByEntityKey.remove(entityKey);
				} else {
					LOG.trace("Remove the token {} from the pool", certificateToRemove.getAbbreviation());
					poolEntity.removeEquivalentCertificate(certificateToRemove);
				}
			}
		}

		synchronized (entitiesByPublicKey) {
			final KeyIdentifier keyIdentifier = new KeyIdentifier(certificateToRemove.getPublicKey());
			EquivalentCertificatesEntity poolEntity = entitiesByPublicKey.get(keyIdentifier);
			if (poolEntity == null) {
				LOG.trace("Key identifier {} is not in the pool", keyIdentifier);
			} else {
				LOG.trace("Key identifier {} is in the pool", keyIdentifier);
				if (poolEntity.getEquivalentCertificates().size() == 1) {
					LOG.trace("Remove the Key identifier {} from the pool", keyIdentifier);
					entitiesByPublicKey.remove(keyIdentifier);
				} else {
					LOG.trace("Remove the token {} from the pool", certificateToRemove.getAbbreviation());
					poolEntity.removeEquivalentCertificate(certificateToRemove);
				}
			}
		}

		synchronized (tokensBySubject) {
			final X500NameIdentifier x500NameIdentifier = new X500NameIdentifier(certificateToRemove.getSubject().getPrincipal());
			Set<CertificateToken> certificateTokens = tokensBySubject.get(x500NameIdentifier);
			if (Utils.isCollectionEmpty(certificateTokens)) {
				LOG.trace("RDN {} is not in the pool", x500NameIdentifier);
			} else {
				if (certificateTokens.size() == 1) {
					tokensBySubject.remove(x500NameIdentifier);
				} else {
					certificateTokens.remove(certificateToRemove);
				}
			}
		}
	}

	/**
	 * This method removes all certificates from the source
	 */
	protected void reset() {
		entitiesByEntityKey = new HashMap<>();
		entitiesByPublicKey = new HashMap<>();
		tokensBySubject = new HashMap<>();
	}

	@Override
	public boolean isKnown(CertificateToken token) {
		final EquivalentCertificatesEntity poolEntity = entitiesByEntityKey.get(token.getEntityKey());
		if (poolEntity != null) {
			Set<CertificateToken> certsByPublicKey = poolEntity.getEquivalentCertificates();
			Set<CertificateToken> certsBySubject = getBySubject(token.getSubject());
			return Utils.containsAny(certsByPublicKey, certsBySubject);
		}
		return false;
	}

	/**
	 * Retrieves the unmodifiable list of all certificate tokens from this source.
	 *
	 * @return all certificates from this source
	 */
	@Override
	public List<CertificateToken> getCertificates() {
		List<CertificateToken> allCertificates = new ArrayList<>();
		for (EquivalentCertificatesEntity entity : entitiesByEntityKey.values()) {
			allCertificates.addAll(entity.getEquivalentCertificates());
		}
		return Collections.unmodifiableList(allCertificates);
	}

	@Override
	public List<CertificateSourceEntity> getEntities() {
		return new ArrayList<>(entitiesByEntityKey.values());
	}

	/**
	 * This method returns a list of {@code CertificateToken} with the given
	 * {@code PublicKey}
	 * 
	 * @param publicKey the public key to find
	 * @return a set of CertificateToken which have the given public key
	 */
	@Override
	public Set<CertificateToken> getByPublicKey(PublicKey publicKey) {
		EquivalentCertificatesEntity entity = entitiesByPublicKey.get(new KeyIdentifier(publicKey));
		if (entity != null) {
			return entity.getEquivalentCertificates();
		} else {
			return Collections.emptySet();
		}
	}

	@Override
	public Set<CertificateToken> getByEntityKey(EntityIdentifier entityKey) {
		EquivalentCertificatesEntity entity = entitiesByEntityKey.get(entityKey);
		if (entity != null) {
			return entity.getEquivalentCertificates();
		} else {
			return Collections.emptySet();
		}
	}

	/**
	 * This method returns a list of {@code CertificateToken} with the given SKI
	 * (SubjectKeyIdentifier (SHA-1 of the PublicKey))
	 * 
	 * @param ski the Subject Key Identifier
	 * @return a set of CertificateToken which have the given ski
	 */
	@Override
	public Set<CertificateToken> getBySki(byte[] ski) {
		for (EquivalentCertificatesEntity entity : entitiesByPublicKey.values()) {
			if (Arrays.equals(entity.getSki(), ski)) {
				return entity.getEquivalentCertificates();
			}
		}
		return Collections.emptySet();
	}
	
	/**
	 * This method returns the Set of certificates with the same subjectDN.
	 *
	 * @param subject the subject to match
	 * @return If no match is found then an empty list is returned.
	 */
	@Override
	public Set<CertificateToken> getBySubject(X500PrincipalHelper subject) {
		final Set<CertificateToken> tokensSet = tokensBySubject.get(new X500NameIdentifier(subject.getPrincipal()));
		if (tokensSet != null) {
			return tokensSet;
		}
		return Collections.emptySet();
	}

	@Override
	public Set<CertificateToken> getBySignerIdentifier(SignerIdentifier signerIdentifier) {
		Set<CertificateToken> result = new HashSet<>();
		for (EquivalentCertificatesEntity entry : entitiesByEntityKey.values()) {
			for (CertificateToken certificateToken : entry.getEquivalentCertificates()) {
				// run over all entries to compare with the SN too
				if (signerIdentifier.isRelatedToCertificate(certificateToken)) {
					result.add(certificateToken);
				}
			}
		}
		return result;
	}

	@Override
	public Set<CertificateToken> getByCertificateDigest(Digest digest) {
		Set<CertificateToken> result = new HashSet<>();
		for (EquivalentCertificatesEntity entry : entitiesByEntityKey.values()) {
			for (CertificateToken certificateToken : entry.getEquivalentCertificates()) {
				if (Arrays.equals(digest.getValue(), certificateToken.getDigest(digest.getAlgorithm()))) {
					result.add(certificateToken);
				}
			}
		}
		return result;
	}
	
	@Override
	public Set<CertificateToken> findTokensFromCertRef(CertificateRef certificateRef) {
		Set<CertificateToken> result = new HashSet<>();
		for (EquivalentCertificatesEntity entry : entitiesByEntityKey.values()) {
			for (CertificateToken certificateToken : entry.getEquivalentCertificates()) {
				if (doesCertificateReferenceMatch(certificateToken, certificateRef)) {
					result.add(certificateToken);
				}
			}
		}
		return result;
	}

	/**
	 * This method verifies whether the {@code CertificateRef} does match to the {@code CertificateToken}
	 *
	 * @param certificateToken {@link CertificateToken} to be verified
	 * @param certificateRef {@link CertificateRef} to be used to
	 * @return TRUE if the certificate reference matches the certificate token, FALSE otherwise
	 */
	protected boolean doesCertificateReferenceMatch(CertificateToken certificateToken, CertificateRef certificateRef) {
		return certificateMatcher.match(certificateToken, certificateRef);
	}

	/**
	 * This method returns the number of stored certificates in this source
	 * 
	 * @return number of certificates in this instance
	 */
	public int getNumberOfCertificates() {
		return getCertificates().size();
	}

	/**
	 * This method returns the number of stored entities (unique public key) in this
	 * source
	 * 
	 * @return number of entities in this instance
	 */
	public int getNumberOfEntities() {
		return entitiesByEntityKey.size();
	}

	@Override
	public CertificateSourceType getCertificateSourceType() {
		return CertificateSourceType.OTHER;
	}

	@Override
	public boolean isTrusted(CertificateToken certificateToken) {
		return false;
	}

	@Override
	public boolean isTrustedAtTime(CertificateToken certificateToken, Date controlTime) {
		return isTrusted(certificateToken);
	}

	@Override
	public boolean isAllSelfSigned() {
		for (CertificateToken certificate : getCertificates()) {
			if (!certificate.isSelfSigned()) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean isCertificateSourceEqual(CertificateSource certificateSource) {
		return new HashSet<>(getCertificates()).equals(new HashSet<>(certificateSource.getCertificates()));
	}

	@Override
	public boolean isCertificateSourceEquivalent(CertificateSource certificateSource) {
		return new HashSet<>(getEntities()).equals(new HashSet<>(certificateSource.getEntities()));
	}

}