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

import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;

/**
 * Represents a source of certificates embedded in a token (signature, timestamp, ocsp response)
 *
 */
@SuppressWarnings("serial")
public abstract class TokenCertificateSource extends CommonCertificateSource {

	/** A map between {@code SignerIdentifier}s and {@code CertificateOrigin}s */
	private final Map<SignerIdentifier, List<CertificateOrigin>> certificateIdentifierOrigins = new LinkedHashMap<>();

	/** A map between {@code CertificateToken}s and {@code CertificateOrigin}s */
	private final Map<CertificateToken, List<CertificateOrigin>> certificateOrigins = new LinkedHashMap<>();

	/** A map between {@code CertificateRef}s and {@code CertificateOrigin}s */
	private final Map<CertificateRef, List<CertificateRefOrigin>> certificateRefOrigins = new LinkedHashMap<>();

	/**
	 * Default constructor
	 */
	protected TokenCertificateSource() {
		super();
	}

	/**
	 * Adds a {@code CertificateIdentifier} with its origin
	 * 
	 * @param signerIdentifier the certificate identifier to be added
	 * @param origin                the origin of the certificate identifier
	 */
	protected void addCertificateIdentifier(SignerIdentifier signerIdentifier, CertificateOrigin origin) {
		Objects.requireNonNull(signerIdentifier, "The certificate identifier cannot be null");
		Objects.requireNonNull(origin, "The origin cannot be null");
		certificateIdentifierOrigins.computeIfAbsent(signerIdentifier, k -> new ArrayList<>()).add(origin);
	}

	/**
	 * Adds a {@code CertificateToken} with its {@code CertificateOrigin}
	 * 
	 * @param certificate the certificate to be added
	 * @param origin      the origin of the certificate
	 */
	protected void addCertificate(CertificateToken certificate, CertificateOrigin origin) {
		Objects.requireNonNull(certificate, "The certificate cannot be null");
		Objects.requireNonNull(origin, "The origin cannot be null");
		certificateOrigins.computeIfAbsent(certificate, k -> new ArrayList<>()).add(origin);
		// TODO remove ?
		addCertificate(certificate);
	}

	/**
	 * Adds a {@code CertificateRef} with its {@code CertificateRefOrigin}
	 * 
	 * @param certificateRef the certificate reference to be added
	 * @param origin         the origin of the certificate reference
	 */
	protected void addCertificateRef(CertificateRef certificateRef, CertificateRefOrigin origin) {
		Objects.requireNonNull(certificateRef, "The certificateRef cannot be null");
		Objects.requireNonNull(origin, "The origin cannot be null");
		certificateRefOrigins.computeIfAbsent(certificateRef, k -> new ArrayList<>()).add(origin);
	}

	/**
	 * Returns list of {@link CertificateRef}s found for the given
	 * {@code certificateToken}
	 * 
	 * @param certificateToken {@link CertificateToken} to find references for
	 * @return list of {@link CertificateRef}s
	 */
	public List<CertificateRef> getReferencesForCertificateToken(CertificateToken certificateToken) {
		List<CertificateRef> result = new ArrayList<>();
		for (CertificateRef certificateRef : certificateRefOrigins.keySet()) {
			if (certificateMatcher.match(certificateToken, certificateRef)) {
				result.add(certificateRef);
			}
		}
		return result;
	}

	/**
	 * Returns Set of {@link CertificateToken}s for the provided
	 * {@link CertificateRef}s
	 * 
	 * @param certificateRefs list of {@link CertificateRef}s
	 * @return Set of {@link CertificateToken}s
	 */
	public Set<CertificateToken> findTokensFromRefs(List<CertificateRef> certificateRefs) {
		Set<CertificateToken> result = new HashSet<>();
		for (CertificateRef certificateRef : certificateRefs) {
			result.addAll(findTokensFromCertRef(certificateRef));
		}
		return result;
	}
	
	/**
	 * Returns a Set of all {@link SignerIdentifier}
	 * 
	 * For CAdES/PAdES/Timestamp
	 * 
	 * @return a set of {@link SignerIdentifier}
	 */
	public Set<SignerIdentifier> getAllCertificateIdentifiers() {
		return certificateIdentifierOrigins.keySet();
	}

	/**
	 * Returns the current {@link SignerIdentifier}
	 * 
	 * For CAdES/PAdES/Timestamp
	 * 
	 * @return the current {@link SignerIdentifier} or null
	 */
	public SignerIdentifier getCurrentCertificateIdentifier() {
		SignerIdentifier current = null;
		for (SignerIdentifier signerIdentifier : getAllCertificateIdentifiers()) {
			if (signerIdentifier.isCurrent()) {
				if (current != null) {
					throw new IllegalStateException("More than one current CertificateIdentifier");
				}
				current = signerIdentifier;
				break;
			}
		}
		return current;
	}

	/**
	 * Returns a Set of all certificate references
	 * 
	 * @return a Set of {@link CertificateRef}s
	 */
	public Set<CertificateRef> getAllCertificateRefs() {
		return certificateRefOrigins.keySet();
	}
	
	/**
	 * Returns a list of orphan certificate refs
	 *
	 * @return list of {@link CertificateRef}s
	 */
	public List<CertificateRef> getOrphanCertificateRefs() {
		List<CertificateRef> result = new ArrayList<>();
		for (CertificateRef certificateRef : certificateRefOrigins.keySet()) {
			if (isOrphan(certificateRef)) {
				result.add(certificateRef);
			}
		}
		return result;
	}

	private boolean isOrphan(CertificateRef certificateRef) {
		for (CertificateToken certificateToken : certificateOrigins.keySet()) {
			if (certificateMatcher.match(certificateToken, certificateRef)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Gets a {@code CertificateToken} by the given {@code SignerIdentifier}
	 *
	 * @param signerIdentifier {@link SignerIdentifier}
	 * @return {@link CertificateToken}
	 */
	protected CertificateToken getCertificateToken(SignerIdentifier signerIdentifier) {
		for (CertificateToken certificateToken : certificateOrigins.keySet()) {
			if (signerIdentifier.isRelatedToCertificate(certificateToken)) {
				return certificateToken;
			}
		}
		return null;
	}

	/**
	 * Gets a list of {@code CertificateToken}s by the given {@code CertificateOrigin}
	 *
	 * @param origin {@link CertificateOrigin}
	 * @return a list of {@link CertificateToken}s
	 */
	protected List<CertificateToken> getCertificateTokensByOrigin(CertificateOrigin origin) {
		List<CertificateToken> result = new LinkedList<>();
		for (Entry<CertificateToken, List<CertificateOrigin>> entry : certificateOrigins.entrySet()) {
			List<CertificateOrigin> currentOrigins = entry.getValue();
			if (Utils.isCollectionNotEmpty(currentOrigins) && currentOrigins.contains(origin)) {
				result.add(entry.getKey());
			}
		}
		return result;
	}

	/**
	 * Gets a list of {@code CertificateRef}s by the given {@code CertificateRefOrigin}
	 *
	 * @param origin {@link CertificateRefOrigin}
	 * @return a list of {@link CertificateRef}s
	 */
	protected List<CertificateRef> getCertificateRefsByOrigin(CertificateRefOrigin origin) {
		List<CertificateRef> result = new LinkedList<>();
		for (Entry<CertificateRef, List<CertificateRefOrigin>> entry : certificateRefOrigins.entrySet()) {
			List<CertificateRefOrigin> currentOrigins = entry.getValue();
			if (Utils.isCollectionNotEmpty(currentOrigins) && currentOrigins.contains(origin)) {
				result.add(entry.getKey());
			}
		}
		return result;
	}
	
	/**
	 * Extracts origins for a given certificateRef
	 * 
	 * @param certificateRef {@link CertificateRef} to get origins for
	 * @return a list of {@link CertificateRefOrigin}s
	 */
	public List<CertificateRefOrigin> getCertificateRefOrigins(CertificateRef certificateRef) {
		List<CertificateRefOrigin> origins = certificateRefOrigins.get(certificateRef);
		if (Utils.isCollectionNotEmpty(origins)) {
			return origins;
		}
		return Collections.emptyList();
	}

}
