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

import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.identifier.IdentifierBasedObject;

import java.io.Serializable;

public class CertificateRef implements IdentifierBasedObject, Serializable {

	private static final long serialVersionUID = -325165164194282066L;
	
	private Digest certDigest;
	private CertificateIdentifier certificateIdentifier; // signature/timestamp source
	private ResponderId responderId; // in case of OCSP response
	
	private CertificateRefOrigin origin;
	
	private Identifier identifier;

	public Digest getCertDigest() {
		return certDigest;
	}

	public void setCertDigest(Digest certDigest) {
		this.certDigest = certDigest;
	}

	public CertificateIdentifier getCertificateIdentifier() {
		return certificateIdentifier;
	}

	public void setCertificateIdentifier(CertificateIdentifier certificateIdentifier) {
		this.certificateIdentifier = certificateIdentifier;
	}

	public ResponderId getResponderId() {
		return responderId;
	}

	public void setResponderId(ResponderId responderId) {
		this.responderId = responderId;
	}
	
	public CertificateRefOrigin getOrigin() {
		return origin;
	}
	
	public void setOrigin(CertificateRefOrigin origin) {
		this.origin = origin;
	}
	
	/**
	 * Returns the certificate reference identifier
	 * @return {@link Identifier}
	 */
	@Override
	public Identifier getDSSId() {
		if (identifier == null) {
			identifier = new CertificateRefIdentifier(this);
		}
		return identifier;
	}
	
	/**
	 * Returns the certificate reference {@link String} id
	 * @return {@link String} id
	 */
	public String getDSSIdAsString() {
		return getDSSId().asXmlId();
	}

	@Override
	public String toString() {
		return "CertificateRef [certDigest=" + certDigest + ", certificateIdentifier=" + certificateIdentifier + ", origin=" + origin + "]";
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
		CertificateRef other = (CertificateRef) obj;
		if (getDSSId() == null) {
			if (other.getDSSId() != null) {
				return false;
			}
		} else if (!getDSSId().equals(other.getDSSId())) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((getDSSId() == null) ? 0 : getDSSId().hashCode());
		return result;
	}

}
