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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.TokenIdentifier;
import eu.europa.esig.dss.tsl.ServiceInfo;

/**
 * This class hosts the set of certificates which is used during the validation process. A certificate can be found in
 * different sources: trusted list, signature, OCSP response... but each certificate is unambiguously identified by its
 * issuer DN and serial number. This class allows to keep only one occurrence of the certificate regardless its
 * provenance. Two pools of certificates can be merged using the {@link #merge(CertificatePool)} method.
 */
public class CertificatePool implements Serializable {

	private static final Logger LOG = LoggerFactory.getLogger(CertificatePool.class);

	/**
	 * Map of encapsulated certificates with unique DSS identifier as key (hash code calculated on issuer distinguished name and serial
	 * number)
	 */
	private Map<TokenIdentifier, CertificateToken> certById = new HashMap<TokenIdentifier, CertificateToken>();

	/**
	 * Map f encapsulated certificates with subject distinguished name as key.
	 */
	private Map<String, List<CertificateToken>> certBySubject = new HashMap<String, List<CertificateToken>>();

	/**
	 * Returns the instance of a certificate token. If the certificate is not referenced yet a new instance of
	 * {@link CertificateToken} is created.
	 *
	 * @param cert
	 * @return
	 */
	public CertificateToken getInstance(final CertificateToken cert, final CertificateSourceType certSource) {

		return getInstance(cert, certSource, (ServiceInfo) null);
	}

	/**
	 * This method returns the instance of a {@link CertificateToken} corresponding to the given {@link X509Certificate}.
	 * If the given certificate is not yet present in the pool it will be added. If the {@link CertificateToken} exists
	 * already in the pool but has no {@link ServiceInfo} this reference will be added.
	 *
	 * @param cert
	 * @param certSource
	 * @param serviceInfo
	 * @return
	 */
	public CertificateToken getInstance(final CertificateToken cert, final CertificateSourceType certSource, final ServiceInfo serviceInfo) {

		final List<ServiceInfo> services = new ArrayList<ServiceInfo>();
		if (serviceInfo != null) {

			services.add(serviceInfo);
		}
		final List<CertificateSourceType> sources = new ArrayList<CertificateSourceType>();
		if (certSource != null) {

			sources.add(certSource);
		}
		return getInstance(cert, sources, services);
	}

	/**
	 * This method returns the instance of a {@link CertificateToken} corresponding to the given {@link X509Certificate}.
	 * If the given certificate is not yet present in the pool it will added. If the {@link CertificateToken} exists
	 * already in the pool but has no {@link ServiceInfo} this reference will be added.
	 *
	 * @param certificateToAdd
	 * @param sources
	 * @param services
	 * @return
	 */
	public CertificateToken getInstance(final CertificateToken certificateToAdd, final List<CertificateSourceType> sources, final List<ServiceInfo> services) {

		if (certificateToAdd == null) {
			throw new NullPointerException();
		}
		
		if (sources == null || sources.size() == 0) {
			throw new IllegalStateException("The certificate source type must be set.");
		}
		
		if (LOG.isTraceEnabled()) {
			LOG.trace("Certificate to add: " + certificateToAdd.getIssuerX500Principal() + "|" + certificateToAdd.getSerialNumber());
		}
		
		final TokenIdentifier id = certificateToAdd.getDSSId();
		synchronized (certById) {

			CertificateToken certToken = certById.get(id);
			if (certToken == null) {

				LOG.debug("Certificate " + certificateToAdd.getDSSId() + " is not in the pool");
				certToken = certificateToAdd;
				certById.put(id, certToken);
				final String subjectName = certificateToAdd.getSubjectX500Principal().getName(X500Principal.CANONICAL);
				List<CertificateToken> list = certBySubject.get(subjectName);
				if (list == null) {

					list = new ArrayList<CertificateToken>();
					certBySubject.put(subjectName, list);
				}
				list.add(certToken);
			} else {

				LOG.debug("Certificate " + certificateToAdd.getDSSId() + " is already in the pool");
				final X509Certificate foundCertificate = certToken.getCertificate();
				final byte[] foundCertificateSignature = foundCertificate.getSignature();
				final byte[] certificateToAddSignature = certificateToAdd.getSignature();
				if (!Arrays.equals(foundCertificateSignature, certificateToAddSignature)) {

					LOG.warn(" Found certificate: " + certToken.getIssuerX500Principal().toString() + "|" + certToken.getSerialNumber());
					LOG.warn("More than one certificate for the same issuer subject name and serial number! The standard is not met by the certificate issuer!");
				}
			}
			for (final CertificateSourceType sourceType : sources) {

				certToken.addSourceType(sourceType);
			}
			if (services != null) {

				for (final ServiceInfo serviceInfo : services) {

					certToken.addServiceInfo(serviceInfo);
				}
			}
			return certToken;
		}
	}

	/**
	 * This method returns an unmodifiable list containing all encapsulated certificate tokens {@link CertificateToken}.
	 *
	 * @return
	 */
	public List<CertificateToken> getCertificateTokens() {

		ArrayList<CertificateToken> certificateTokenArrayList = new ArrayList<CertificateToken>(certById.values());
		return Collections.unmodifiableList(certificateTokenArrayList);
	}

	/**
	 * This method return the number  of certificates contained by this pool.
	 *
	 * @return the number of certificates
	 */
	public int getNumberOfCertificates() {

		return certById.size();
	}

	/**
	 * This method allows to add certificates from another {@link CertificatePool}. If an instance of the
	 * {@link CertificateToken} already exists in this pool only the {@link ServiceInfo} and
	 * {@link CertificateSourceType} are added.
	 *
	 * @param certPool
	 */
	public void merge(final CertificatePool certPool) {

		Collection<CertificateToken> certTokens = certPool.getCertificateTokens();
		for (CertificateToken certificateToken : certTokens) {

			CertificateToken cert = certificateToken;
			List<CertificateSourceType> sources = certificateToken.getSources();
			List<ServiceInfo> services = certificateToken.getAssociatedTSPS();
			getInstance(cert, sources, services);
		}
	}

	/**
	 * This method returns the list of certificates with the same issuerDN.
	 *
	 * @param x500Principal subject distinguished name to match.
	 * @return If no match is found then an empty list is returned.
	 */
	public List<CertificateToken> get(final X500Principal x500Principal) {

		List<CertificateToken> certificateTokenList = null;
		if (x500Principal != null) {

			/**
			 * TODO: (Bob: 2014 Feb 21) For some certificates the comparison based on X500Principal.CANONICAL does not returns the same result as this based on X500Principal
			 * .RFC2253. The CANONICAL form seems to be compliant with the requirements of RFC 2459.
			 * The returned list can be maybe enriched by RFC2253 form?
			 */
			final String x500PrincipalCanonicalized = x500Principal.getName(X500Principal.CANONICAL);
			certificateTokenList = certBySubject.get(x500PrincipalCanonicalized);
		}
		if (certificateTokenList == null) {

			certificateTokenList = new ArrayList<CertificateToken>();
		}
		return Collections.unmodifiableList(certificateTokenList);
	}
}
