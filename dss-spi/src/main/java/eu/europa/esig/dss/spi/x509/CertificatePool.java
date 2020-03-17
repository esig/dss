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

import java.io.Serializable;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.identifier.EntityIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class hosts the set of certificates which is used during the validation
 * process. A certificate can be found in different sources: trusted list,
 * signature, OCSP response... but each certificate is unambiguously identified
 * by its issuer DN and serial number. This class allows to keep only one
 * occurrence of the certificate regardless its provenance. A CertificateSource
 * can be imported with the {@link #importCerts(CertificateSource)} method .
 */
public class CertificatePool implements Serializable {

	private static final long serialVersionUID = -3933224032299663242L;

	private static final Logger LOG = LoggerFactory.getLogger(CertificatePool.class);

	/*
	 * Map of entries, the key is a hash of the public key.
	 * 
	 * All entries share the same keypair
	 */
	private Map<EntityIdentifier, CertificatePoolEntity> entriesByPublicKeyHash = new HashMap<>();

	/*
	 * Map of tokens, the key is the canonicalized SubjectX500Principal
	 * 
	 * For a same SubjectX500Principal, different keypairs are possible
	 */
	private Map<String, Set<CertificateToken>> tokensBySubject = new HashMap<>();

	public CertificatePool() {
		LOG.debug("New CertificatePool created");
	}

	/**
	 * This method returns the instance of a {@link CertificateToken}.
	 *
	 * @param certificateToAdd
	 *                         the certificate to add in the pool
	 * @param certSource
	 *                         the source of the given certificate
	 * @return the complete CertificateToken instance (merged with the pool content)
	 */
	public CertificateToken getInstance(final CertificateToken certificateToAdd, final CertificateSourceType certSource) {
		Objects.requireNonNull(certificateToAdd, "The certificate must be filled");
		Objects.requireNonNull(certSource, "The certificate source type must be set.");

		if (LOG.isTraceEnabled()) {
			LOG.trace("Certificate to add: {} | {}", certificateToAdd.getIssuerX500Principal(), certificateToAdd.getSerialNumber());
		}

		synchronized (entriesByPublicKeyHash) {
			final EntityIdentifier entityKey = certificateToAdd.getEntityKey();
			CertificatePoolEntity poolEntity = entriesByPublicKeyHash.get(entityKey);
			if (poolEntity == null) {
				LOG.trace("Public key {} is not in the pool", entityKey);
				poolEntity = new CertificatePoolEntity(certificateToAdd, certSource);
				entriesByPublicKeyHash.put(entityKey, poolEntity);
			} else {
				LOG.trace("Public key {} is already in the pool", entityKey);
				poolEntity.addEquivalentCertificate(certificateToAdd);
				poolEntity.addSource(certSource);
			}
		}
		
		synchronized (tokensBySubject) {
			String canonicalizedSubject = certificateToAdd.getCanonicalizedSubject();
			Set<CertificateToken> tokensSet = tokensBySubject.get(canonicalizedSubject);
			if (tokensSet == null) {
				tokensSet = new HashSet<>();
				tokensBySubject.put(canonicalizedSubject, tokensSet);
			}
			tokensSet.add(certificateToAdd);
		}
		
		return certificateToAdd;
	}

	public boolean isTrusted(CertificateToken cert) {
		final CertificatePoolEntity poolEntity = getPoolEntry(cert);
		return poolEntity != null && poolEntity.isTrusted();
	}

	public Set<CertificateSourceType> getSources(CertificateToken certificateToken) {
		final CertificatePoolEntity poolEntity = getPoolEntry(certificateToken);
		if (poolEntity != null) {
			return poolEntity.getSources();
		} else {
			return Collections.emptySet();
		}
	}

	/**
	 * This method returns all known issuers for the given token.
	 * 
	 * @param token
	 *              the child certificate, timestamp or revocation data for which
	 *              the issuers are required
	 * @return a {@code List} of all known {@code CertificateToken}
	 */
	public List<CertificateToken> getIssuers(final Token token) {
		if (token.getPublicKeyOfTheSigner() != null) {
			return get(token.getPublicKeyOfTheSigner());
		} else if (token.getIssuerX500Principal() != null) {
			Set<CertificateToken> potentialIssuers = get(token.getIssuerX500Principal());
			for (CertificateToken potentialIssuer : potentialIssuers) {
				if (token.isSignedBy(potentialIssuer)) {
					return get(potentialIssuer.getPublicKey());
				}
			}
		}
		return Collections.emptyList();
	}

	/**
	 * THis method returns an issuer for the given token
	 * 
	 * @param token
	 *              the child certificate, timestamp or revocation data for which an
	 *              issuer is required
	 * @return an issuer which is valid on the token creation, or a matched issuer
	 *         with the public key or null
	 */
	public CertificateToken getIssuer(final Token token) {
		List<CertificateToken> issuers = getIssuers(token);
		if (Utils.isCollectionNotEmpty(issuers)) {
			for (CertificateToken issuer : issuers) {
				if (issuer.isValidOn(token.getCreationDate())) {
					return issuer;
				}
			}
			LOG.warn("No issuer found for the token creation date. The process continues with an issuer which has the same public key.");
			return issuers.iterator().next();
		} else {
			return null;
		}
	}

	public CertificateToken getTrustAnchor(CertificateToken cert) {
		CertificatePoolEntity poolEntity = getPoolEntry(cert);
		while (poolEntity != null) {
			List<CertificateToken> certificates = poolEntity.getEquivalentCertificates();
			if (poolEntity.isTrusted()) {
				return certificates.iterator().next();
			}

			List<PublicKey> pubKeyIssuers = new ArrayList<>();
			for (CertificateToken certificateToken : certificates) {
				if (!certificateToken.isSelfIssued() && certificateToken.getPublicKeyOfTheSigner() != null) {
					pubKeyIssuers.add(certificateToken.getPublicKeyOfTheSigner());
				}
			}

			if (!pubKeyIssuers.isEmpty()) {
				if (pubKeyIssuers.size() > 1) {
					LOG.warn("More than one path found");
				}
				poolEntity = getPoolEntry(pubKeyIssuers.iterator().next());
			}
		}
		return null;
	}

	/**
	 * This method returns the Set of certificates with the same subjectDN.
	 *
	 * @param x500Principal
	 *                      subject distinguished name to match.
	 * @return If no match is found then an empty list is returned.
	 */
	public Set<CertificateToken> get(final X500Principal x500Principal) {
		final Set<CertificateToken> tokensSet = tokensBySubject.get(canonicalize(x500Principal));
		if (tokensSet != null) {
			return tokensSet;
		}
		return Collections.emptySet();
	}

	/**
	 * This method returns the List of certificates with the same Public key.
	 *
	 * @param publicKey
	 *                  expected public key.
	 * @return If no match is found then an empty list is returned.
	 */
	public List<CertificateToken> get(PublicKey publicKey) {
		final CertificatePoolEntity poolEntity = entriesByPublicKeyHash.get(getPublicKeyHash(publicKey));
		if (poolEntity != null) {
			return poolEntity.getEquivalentCertificates();
		}
		return Collections.emptyList();
	}

	/**
	 * This method returns the List of certificates with the same SKI (subject key
	 * identifier = SHA-1 of the Public Key).
	 *
	 * @param expectedSki
	 *                    expected SKI value.
	 * @return If no match is found then an empty list is returned.
	 */
	public List<CertificateToken> getBySki(final byte[] expectedSki) {
		Collection<CertificatePoolEntity> values = entriesByPublicKeyHash.values();
		for (CertificatePoolEntity entity : values) {
			if (Arrays.equals(expectedSki, entity.getSki())) {
				return entity.getEquivalentCertificates();
			}
		}
		return Collections.emptyList();
	}

	/**
	 * This method returns the List of certificates with the same serialInfo.
	 *
	 * @param serialInfo
	 *                 expected {@link SerialInfo}
	 * @return If no match is found then an empty list is returned.
	 */
	public List<CertificateToken> getBySerialInfo(SerialInfo serialInfo) {
		Collection<CertificatePoolEntity> values = entriesByPublicKeyHash.values();
		for (CertificatePoolEntity entity : values) {
			List<CertificateToken> equivalentCertificates = entity.getEquivalentCertificates();
			// matches by SN + IssuerName
			List<CertificateToken> result = DSSASN1Utils.filterCertificatesBySerialInfo(serialInfo, equivalentCertificates);
			if (Utils.isCollectionNotEmpty(result)) {
				return result;
			}
		}
		return Collections.emptyList();
	}

	private CertificatePoolEntity getPoolEntry(CertificateToken cert) {
		return entriesByPublicKeyHash.get(cert.getEntityKey());
	}

	private CertificatePoolEntity getPoolEntry(PublicKey pubKey) {
		return entriesByPublicKeyHash.get(getPublicKeyHash(pubKey));
	}

	private EntityIdentifier getPublicKeyHash(PublicKey pk) {
		return new EntityIdentifier(pk);
	}

	private String canonicalize(final X500Principal x500Principal) {
		return x500Principal.getName(X500Principal.CANONICAL);
	}

	/**
	 * This method allows to imports certificates from a
	 * {@link CommonCertificateSource}. If an instance of the
	 * {@link CertificateToken} already exists in this pool only the
	 * {@link CertificateSourceType} are added.
	 *
	 * @param certificateSource
	 *                          the certificate source where certificates will be
	 *                          copied
	 */
	public void importCerts(final CertificateSource certificateSource) {
		final List<CertificateToken> unmodifiableList = certificateSource.getCertificates();
		final CertificateSourceType source = certificateSource.getCertificateSourceType();
		for (CertificateToken certificateToImport : unmodifiableList) {
			getInstance(certificateToImport, source);
		}
	}

	/**
	 * This method return the number of entities contained by this pool identified
	 * by its public key.
	 *
	 * @return the number of entities
	 */
	public int getNumberOfEntities() {
		return entriesByPublicKeyHash.size();
	}

	/**
	 * This method return the number of certificates contained by this pool.
	 *
	 * @return the number of certificates
	 */
	public int getNumberOfCertificates() {
		int i = 0;
		for (CertificatePoolEntity entity : entriesByPublicKeyHash.values()) {
			i += entity.getEquivalentCertificates().size();
		}
		return i;
	}

	public List<CertificateToken> getCertificateTokens() {
		List<CertificateToken> certs = new ArrayList<>();
		for (CertificatePoolEntity entity : entriesByPublicKeyHash.values()) {
			certs.addAll(entity.getEquivalentCertificates());
		}
		return certs;
	}

}
