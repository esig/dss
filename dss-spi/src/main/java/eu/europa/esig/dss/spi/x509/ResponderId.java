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

import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;

public class ResponderId {
	
	private X500Principal subjectX500Principal;
	private byte[] ski;

	public X500Principal getX500Principal() {
		return subjectX500Principal;
	}
	
	public void setX500Principal(X500Principal subjectX500Principal) {
		this.subjectX500Principal = subjectX500Principal;
	}
	
	public byte[] getSki() {
		return ski;
	}
	
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
