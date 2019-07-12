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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.enumerations.CertificateSourceType;

/**
 * This class re-groups equivalent certificates.
 * 
 * All certificates for a given {@code CertificatePoolEntity} have the same
 * public key.
 */
class CertificatePoolEntity implements Serializable {
	
	private static final long serialVersionUID = -8670353777128605464L;

	private static final Logger LOG = LoggerFactory.getLogger(CertificatePoolEntity.class);

	/**
	 * Unique Id for all certificates (SHA-256 of the common public key) 
	 */
	private final String id;
	
	/**
	 * Subject Key Identifier (SHA-1 of the common public key) 
	 */
	private final byte[] ski;

	/**
	 * Equivalent certificates (which have the same public key)
	 */
	private final List<CertificateToken> equivalentCertificates = new ArrayList<CertificateToken>();

	/**
	 * This Set contains the different sources for this certificate.
	 */
	private final Set<CertificateSourceType> sources = new HashSet<CertificateSourceType>();

	CertificatePoolEntity(CertificateToken initialCert, CertificateSourceType source) {
		id = initialCert.getEntityKey();
		ski = DSSASN1Utils.computeSkiFromCert(initialCert);
		equivalentCertificates.add(initialCert);
		sources.add(source);
	}

	void addEquivalentCertificate(CertificateToken token) {
		if (!equivalentCertificates.contains(token)) {
			LOG.trace("Certificate with same public key detected : {}", token.getAbbreviation());
			// we manually recompute the SKI (we had cases with wrongly encoded value in the
			// certificate)
			final byte[] newSKI = DSSASN1Utils.computeSkiFromCert(token);
			// This should never happen
			if (!Arrays.equals(newSKI, ski)) {
				LOG.warn("Token {} is skipped", token);
			} else {
				equivalentCertificates.add(token);
			}
		}
	}
	
	byte[] getSki() {
		return ski;
	}

	void addSource(CertificateSourceType source) {
		sources.add(source);
	}

	List<CertificateToken> getEquivalentCertificates() {
		return Collections.unmodifiableList(equivalentCertificates);
	}

	Set<CertificateSourceType> getSources() {
		return Collections.unmodifiableSet(sources);
	}

	boolean isTrusted() {
		return sources.contains(CertificateSourceType.TRUSTED_LIST) || sources.contains(CertificateSourceType.TRUSTED_STORE);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((id == null) ? 0 : id.hashCode());
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
		CertificatePoolEntity other = (CertificatePoolEntity) obj;
		if (id == null) {
			if (other.id != null) {
				return false;
			}
		} else if (!id.equals(other.id)) {
			return false;
		}
		return true;
	}

}
