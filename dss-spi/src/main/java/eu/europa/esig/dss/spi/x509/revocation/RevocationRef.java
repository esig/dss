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
package eu.europa.esig.dss.spi.x509.revocation;

import java.io.Serializable;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.utils.Utils;

public abstract class RevocationRef implements Serializable {

	private static final long serialVersionUID = 7313118727647264457L;

	private final Digest digest; // can be null
	private final Set<RevocationRefOrigin> origins;
	
	private Identifier identifier;
	
	protected RevocationRef(final Digest digest, RevocationRefOrigin origin) {
		this.digest = digest;
		this.origins = new HashSet<>(Arrays.asList(origin));
	}

	public Digest getDigest() {
		return digest;
	}
	
	public Set<RevocationRefOrigin> getOrigins() {
		return origins;
	}
	
	public void addOrigin(RevocationRefOrigin revocationRefOrigin) {
		origins.add(revocationRefOrigin);
	}
	
	/**
	 * Returns the revocation ref DSS Identifier
	 * 
	 * @return {@link Identifier}
	 */
	public Identifier getDSSId() {
		if (identifier == null) {
			identifier = createIdentifier();
		}
		return identifier;
	}
	
	protected Identifier createIdentifier() {
		return new RevocationRefIdentifier(this);
	}
	
	/**
	 * Returns revocation reference {@link String} id
	 * @return {@link String} id
	 */
	public String getDSSIdAsString() {
		return getDSSId().asXmlId();
	}
	
	@Override
	public String toString() {
		return Utils.toBase64(digest.getValue());
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
		RevocationRef other = (RevocationRef) obj;
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
