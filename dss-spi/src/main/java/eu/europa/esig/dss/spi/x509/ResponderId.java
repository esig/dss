/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;

import javax.security.auth.x500.X500Principal;
import java.io.Serializable;
import java.util.Arrays;

/**
 * This class represents a ResponderId extracted from an OCSP response
 */
public class ResponderId implements Serializable {

	private static final long serialVersionUID = 651463368797656154L;

	/** The {@code X500Principal} of the OCSP issuer */
	private X500Principal subjectX500Principal;

	/** SKI if the OCSP issuer */
	private byte[] ski;

	/**
	 * Default constructor
	 *
	 * @param subjectX500Principal {@link X500Principal}
	 * @param ski byte array
	 */
	public ResponderId(X500Principal subjectX500Principal, byte[] ski) {
		super();
		this.subjectX500Principal = subjectX500Principal;
		this.ski = ski;
	}

	/**
	 * Gets {@code X500Principal} of the OCSP issuer
	 *
	 * @return {@link X500Principal}
	 */
	public X500Principal getX500Principal() {
		return subjectX500Principal;
	}
	
	/**
	 * Sets {@code X500Principal} of the OCSP issuer
	 *
	 * @param subjectX500Principal {@link X500Principal}
	 */
	public void setX500Principal(X500Principal subjectX500Principal) {
		this.subjectX500Principal = subjectX500Principal;
	}
	
	/**
	 * Gets the SKI of the issuer
	 *
	 * @return byte array
	 */
	public byte[] getSki() {
		return ski;
	}
	
	/**
	 * Sets the SKI of the issuer
	 *
	 * @param ski byte array
	 */
	public void setSki(byte[] ski) {
		this.ski = ski;
	}
	
	/**
	 * Checks if the ResponderId is related to a provided certificateToken
	 * 
	 * @param certificateToken {@link CertificateToken} to check
	 * @return TRUE if the certificateToken is related to the ResponderId, FALSE otherwise
	 */
	public boolean isRelatedToCertificate(CertificateToken certificateToken) {
		if (subjectX500Principal!= null) {
			return DSSASN1Utils.x500PrincipalAreEquals(certificateToken.getSubject().getPrincipal(), subjectX500Principal);
		} else {
			return DSSASN1Utils.isSkiEqual(ski, certificateToken);
		}
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(ski);
		result = prime * result + ((subjectX500Principal == null) ? 0 : subjectX500Principal.hashCode());
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
		ResponderId other = (ResponderId) obj;
		if (!Arrays.equals(ski, other.ski)) {
			return false;
		}
		if (subjectX500Principal == null) {
			if (other.subjectX500Principal != null) {
				return false;
			}
		} else if (!subjectX500Principal.equals(other.subjectX500Principal)) {
			return false;
		}
		return true;
	}
	
}
