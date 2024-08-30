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

import eu.europa.esig.dss.model.identifier.EntityIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * This class re-groups equivalent certificates by a given property (e.g. a public key or entity key).
 * All certificates for a given {@code CertificateSourceEntity} share (at least) the same public key.
 *
 */
class EquivalentCertificatesEntity implements CertificateSourceEntity {
	
	private static final long serialVersionUID = -8670353777128605464L;

	private static final Logger LOG = LoggerFactory.getLogger(CertificateSourceEntity.class);

	/**
	 * Unique Id for all certificates (SHA-256 of the common public key) 
	 */
	private final EntityIdentifier identifier;
	
	/**
	 * Subject Key Identifier (SHA-1 of the common public key) 
	 */
	private final byte[] ski;

	/**
	 * Equivalent certificates (which have the same public key)
	 */
	private final Set<CertificateToken> equivalentCertificates = new HashSet<>();

	/**
	 * Default constructor
	 *
	 * @param initialCert {@link CertificateToken} to instantiate certificate source entity with
	 */
	EquivalentCertificatesEntity(CertificateToken initialCert) {
		identifier = initialCert.getEntityKey();
		ski = DSSASN1Utils.computeSkiFromCert(initialCert);
		equivalentCertificates.add(initialCert);
	}

	/**
	 * Adds a certificate token to the given list of equivalent certificates
	 *
	 * @param token {@link CertificateToken} to add
	 */
	void addEquivalentCertificate(CertificateToken token) {
		if (!equivalentCertificates.contains(token)) {
			LOG.trace("Certificate with same public key detected : {}", token.getAbbreviation());
			// we manually recompute the SKI (we had cases with wrongly encoded value in the
			// certificate)
			final byte[] newSKI = DSSASN1Utils.computeSkiFromCert(token);
			// This should never happen
			if (!Arrays.equals(newSKI, ski)) {
				LOG.warn("Token {} is skipped", token.getAbbreviation());
			} else {
				equivalentCertificates.add(token);
			}
		}
	}

	/**
	 * Removes a certificate token from the given list of equivalent certificates
	 *
	 * @param token {@link CertificateToken} to remove
	 */
	void removeEquivalentCertificate(CertificateToken token) {
		if (equivalentCertificates.contains(token)) {
			if (equivalentCertificates.size() == 1) {
				LOG.warn("Only one token found in the pool. Empty pool is not allowed. " +
						"Removing of token {} is skipped.", token.getAbbreviation());
			} else {
				LOG.trace("Removing certificate from the pool : {}", token.getAbbreviation());
				equivalentCertificates.remove(token);
			}
		}
	}
	
	/**
	 * Gets a Subject Key Identifier (SHA-1 of the common public key)
	 *
	 * @return byte array representing a SKI
	 */
	byte[] getSki() {
		return ski;
	}

	/**
	 * Gets a set of equivalent certificate tokens present within the current instance
	 *
	 * @return a set of {@link CertificateToken}s
	 */
	Set<CertificateToken> getEquivalentCertificates() {
		return Collections.unmodifiableSet(equivalentCertificates);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((identifier == null) ? 0 : identifier.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		EquivalentCertificatesEntity other = (EquivalentCertificatesEntity) obj;
		if (identifier == null) {
			if (other.identifier != null) {
				return false;
			}
		} else if (!identifier.equals(other.identifier)) {
			return false;
		}
		return true;
	}

}
