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
package eu.europa.esig.dss.x509;

import java.io.Serializable;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.EntityIdentifier;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class hosts the set of certificates which is used during the validation
 * process. A certificate can be found in different sources: trusted list,
 * signature, OCSP response... but each certificate is unambiguously identified
 * by its issuer DN and serial number. This class allows to keep only one
 * occurrence of the certificate regardless its provenance. Two pools of
 * certificates can be merged using the {@link #merge(CertificatePool)} method.
 */
public class CertificatePool implements Serializable {

	private static final long serialVersionUID = -3933224032299663242L;

	private static final Logger LOG = LoggerFactory.getLogger(CertificatePool.class);

	private Map<String, CertificatePoolEntity> entriesByPublicKeyHash = new HashMap<String, CertificatePoolEntity>();

	private Map<String, CertificatePoolEntity> entriesBySubject = new HashMap<String, CertificatePoolEntity>();

	public CertificatePool() {
		LOG.debug("New CertificatePool created");
	}

	/**
	 * Returns the instance of a certificate token. If the certificate is not
	 * referenced yet a new instance of {@link CertificateToken} is created.
	 *
	 * @param cert
	 *                   the certificate to add in the pool
	 * @param certSource
	 *                   the source of the given certificate
	 * @return the complete CertificateToken instance (merged with the pool content)
	 * 
	 */
	public CertificateToken getInstance(final CertificateToken cert, final CertificateSourceType certSource) {
		return getInstance(cert, certSource, (ServiceInfo) null);
	}

	/**
	 * This method returns the instance of a {@link CertificateToken} corresponding
	 * to the given {@link X509Certificate} . If the given certificate is not yet
	 * present in the pool it will be added. If the {@link CertificateToken} exists
	 * already in the pool but has no {@link ServiceInfo} this reference will be
	 * added.
	 *
	 * @param cert
	 *                    the certificate to add in the pool
	 * @param certSource
	 *                    the source of the given certificate
	 * @param serviceInfo
	 *                    the linked trust service info
	 * @return the complete CertificateToken instance (merged with the pool content)
	 */
	public CertificateToken getInstance(final CertificateToken cert, final CertificateSourceType certSource, final ServiceInfo serviceInfo) {
		final Set<ServiceInfo> services = new HashSet<ServiceInfo>();
		if (serviceInfo != null) {
			services.add(serviceInfo);
		}
		final Set<CertificateSourceType> sources = new HashSet<CertificateSourceType>();
		if (certSource != null) {
			sources.add(certSource);
		}
		return getInstance(cert, sources, services);
	}

	/**
	 * This method returns the instance of a {@link CertificateToken} corresponding
	 * to the given {@link X509Certificate} . If the given certificate is not yet
	 * present in the pool it will added. If the {@link CertificateToken} exists
	 * already in the pool but has no {@link ServiceInfo} this reference will be
	 * added.
	 *
	 * @param certificateToAdd
	 *                         the certificate to add in the pool
	 * @param sources
	 *                         the sources of the given certificate
	 * @param services
	 *                         the linked trust service infos
	 * @return the complete CertificateToken instance (merged with the pool content)
	 */
	public CertificateToken getInstance(final CertificateToken certificateToAdd, final Set<CertificateSourceType> sources, final Set<ServiceInfo> services) {
		if (certificateToAdd == null) {
			throw new NullPointerException("The certificate must be filled");
		}

		if (Utils.isCollectionEmpty(sources)) {
			throw new IllegalStateException("The certificate source type must be set.");
		}

		if (LOG.isTraceEnabled()) {
			LOG.trace("Certificate to add: " + certificateToAdd.getIssuerX500Principal() + "|" + certificateToAdd.getSerialNumber());
		}

		final String entityKey = certificateToAdd.getEntityKey();
		synchronized (entityKey) {
			CertificatePoolEntity poolEntity = entriesByPublicKeyHash.get(entityKey);
			if (poolEntity == null) {
				LOG.trace("Public key " + entityKey + " is not in the pool");
				poolEntity = new CertificatePoolEntity(certificateToAdd);
				entriesByPublicKeyHash.put(entityKey, poolEntity);
				entriesBySubject.put(getCanonicalizedSubject(certificateToAdd), poolEntity);
			} else {
				LOG.trace("Public key " + entityKey + " is already in the pool");
				poolEntity.addEquivalentCertificate(certificateToAdd);
			}

			poolEntity.addRelatedTrustServices(services);

			for (final CertificateSourceType sourceType : sources) {
				certificateToAdd.addSourceType(sourceType);
			}
		}
		return certificateToAdd;
	}

	public boolean isTrusted(CertificateToken cert) {
		final CertificatePoolEntity poolEntity = getPoolEntry(cert);
		return poolEntity != null && poolEntity.isTrusted();
	}

	public Set<ServiceInfo> getRelatedTrustServices(CertificateToken cert) {
		final CertificatePoolEntity poolEntity = getPoolEntry(cert);
		if (poolEntity != null) {
			return poolEntity.getRelatedTrustServices();
		}
		return Collections.emptySet();
	}

	public List<CertificateToken> getIssuers(Token token) {
		if (token.getPublicKeyOfTheSigner() != null) {
			return get(token.getPublicKeyOfTheSigner());
		} else if (token.getIssuerX500Principal() != null) {
			List<CertificateToken> potentialIssuers = get(token.getIssuerX500Principal());
			for (CertificateToken potentialIssuer : potentialIssuers) {
				if (token.isSignedBy(potentialIssuer.getPublicKey())) {
					return potentialIssuers;
				}
			}
		}
		return Collections.emptyList();
	}

	public CertificateToken getIssuer(Token token) {
		List<CertificateToken> issuers = getIssuers(token);
		if (!issuers.isEmpty()) {
			return issuers.iterator().next();
		} else {
			return null;
		}
	}

	public CertificateToken getBestIssuer(Token token) {
		List<CertificateToken> issuers = getIssuers(token);
		if (!issuers.isEmpty()) {
			for (CertificateToken issuer : issuers) {
				if (issuer.isTrusted()) {
					return issuer;
				}
			}
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

			List<PublicKey> pubKeyIssuers = new ArrayList<PublicKey>();
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
	public List<CertificateToken> get(final X500Principal x500Principal) {
		final CertificatePoolEntity poolEntity = entriesBySubject.get(canonicalize(x500Principal));
		if (poolEntity != null) {
			return poolEntity.getEquivalentCertificates();
		}
		return Collections.emptyList();
	}

	public List<CertificateToken> get(PublicKey publicKey) {
		final CertificatePoolEntity poolEntity = entriesByPublicKeyHash.get(getPublicKeyHash(publicKey));
		if (poolEntity != null) {
			return poolEntity.getEquivalentCertificates();
		}
		return Collections.emptyList();
	}

	public List<CertificateToken> getBySki(byte[] expectedSki) {
		Collection<CertificatePoolEntity> values = entriesByPublicKeyHash.values();
		for (CertificatePoolEntity entity : values) {
			List<CertificateToken> certificates = entity.getEquivalentCertificates();
			CertificateToken first = certificates.iterator().next();
			byte[] computedSki = DSSASN1Utils.getSki(first, true);
			if (Arrays.equals(expectedSki, computedSki)) {
				return certificates;
			}
		}
		return Collections.emptyList();
	}

	private String canonicalize(final X500Principal x500Principal) {
		return x500Principal.getName(X500Principal.CANONICAL);
	}

	private CertificatePoolEntity getPoolEntry(CertificateToken cert) {
		return entriesByPublicKeyHash.get(cert.getEntityKey());
	}

	private CertificatePoolEntity getPoolEntry(PublicKey pubKey) {
		return entriesByPublicKeyHash.get(getPublicKeyHash(pubKey));
	}

	private String getPublicKeyHash(PublicKey pk) {
		EntityIdentifier id = new EntityIdentifier(pk);
		return id.asXmlId();
	}

	private String getCanonicalizedSubject(CertificateToken cert) {
		return canonicalize(cert.getSubjectX500Principal());
	}

	/**
	 * This method allows to add certificates from another {@link CertificatePool}.
	 * If an instance of the {@link CertificateToken} already exists in this pool
	 * only the {@link ServiceInfo} and {@link CertificateSourceType} are added.
	 *
	 * @param certPool
	 *                 the certificate pool to merge
	 */
	public void merge(final CertificatePool certPool) {
		final Map<String, CertificatePoolEntity> toImport = certPool.entriesByPublicKeyHash;
		for (CertificatePoolEntity entity : toImport.values()) {
			List<CertificateToken> certificates = entity.getEquivalentCertificates();
			Set<ServiceInfo> trustServices = entity.getRelatedTrustServices();
			for (CertificateToken certificateToImport : certificates) {
				getInstance(certificateToImport, certificateToImport.getSources(), trustServices);
			}
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
			i += entity.equivalentCertificates.size();
		}
		return i;
	}

	public List<CertificateToken> getCertificateTokens() {
		List<CertificateToken> certs = new ArrayList<CertificateToken>();
		for (CertificatePoolEntity entity : entriesByPublicKeyHash.values()) {
			certs.addAll(entity.getEquivalentCertificates());
		}
		return certs;
	}

	private class CertificatePoolEntity {

		private List<CertificateToken> equivalentCertificates = new ArrayList<CertificateToken>();

		private Set<ServiceInfo> relatedTrustServices;

		public CertificatePoolEntity(CertificateToken initialCert) {
			equivalentCertificates.add(initialCert);
		}

		public void addEquivalentCertificate(CertificateToken token) {
			if (!equivalentCertificates.contains(token)) {
				LOG.debug("Certificate with same public key detected : {}", token.getAbbreviation());
				equivalentCertificates.add(token);
			}
		}

		public void addRelatedTrustServices(Set<ServiceInfo> trustServices) {
			if (relatedTrustServices == null) {
				relatedTrustServices = new HashSet<ServiceInfo>();
			}
			for (ServiceInfo serviceInfo : trustServices) {
				relatedTrustServices.add(serviceInfo);
			}
		}

		public List<CertificateToken> getEquivalentCertificates() {
			return Collections.unmodifiableList(equivalentCertificates);
		}

		public Set<ServiceInfo> getRelatedTrustServices() {
			return Collections.unmodifiableSet(relatedTrustServices);
		}

		public boolean isTrusted() {
			for (CertificateToken certificateToken : equivalentCertificates) {
				if (certificateToken.isTrusted()) {
					return true;
				}
			}
			return false;
		}

	}

}
