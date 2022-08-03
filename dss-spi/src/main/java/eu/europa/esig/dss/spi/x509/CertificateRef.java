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

import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.identifier.IdentifierBasedObject;

import java.io.Serializable;

/**
 * This class represents a Certificate Reference entry extracted from a signature
 *
 */
public class CertificateRef implements IdentifierBasedObject, Serializable {

	private static final long serialVersionUID = -325165164194282066L;
	
	/** The digest of the certificate */
	private Digest certDigest;

	/** ASN.1 SignerId (signature or timestamp) */
	private SignerIdentifier signerIdentifier;

	/** ResponderId in case of OCSP response */
	private ResponderId responderId;
	
	/** An unique identifier of the reference */
	private Identifier identifier;

	/**
	 * Default constructor instantiating object with null values
	 */
	public CertificateRef() {
		// empty
	}

	/**
	 * Gets the certificate digest
	 *
	 * @return {@link Digest}
	 */
	public Digest getCertDigest() {
		return certDigest;
	}

	/**
	 * Sets the certificate digest
	 *
	 * @param certDigest {@link Digest}
	 */
	public void setCertDigest(Digest certDigest) {
		this.certDigest = certDigest;
	}

	/**
	 * Gets the {@code SignerIdentifier} (for a reference extracted from a signature or timestamp, when present)
	 *
	 * @return {@link SignerIdentifier}
	 */
	public SignerIdentifier getCertificateIdentifier() {
		return signerIdentifier;
	}

	/**
	 * Sets the {@code SignerIdentifier}
	 *
	 * @param signerIdentifier {@link SignerIdentifier}
	 */
	public void setCertificateIdentifier(SignerIdentifier signerIdentifier) {
		this.signerIdentifier = signerIdentifier;
	}

	/**
	 * Gets the {@code ResponderId} (for a reference extracted from an OCSP response)
	 *
	 * @return {@link SignerIdentifier}
	 */
	public ResponderId getResponderId() {
		return responderId;
	}

	/**
	 * Sets the {@code ResponderId}
	 *
	 * @param responderId {@link ResponderId}
	 */
	public void setResponderId(ResponderId responderId) {
		this.responderId = responderId;
	}
	
	/**
	 * Returns the certificate reference identifier
	 *
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
	 *
	 * @return {@link String} id
	 */
	public String getDSSIdAsString() {
		return getDSSId().asXmlId();
	}

	@Override
	public String toString() {
		return "CertificateRef [certDigest=" + certDigest + ", signerIdentifier=" + signerIdentifier + "]";
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
