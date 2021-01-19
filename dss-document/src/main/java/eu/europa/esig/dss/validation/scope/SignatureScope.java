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
package eu.europa.esig.dss.validation.scope;

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.identifier.IdentifierBasedObject;
import eu.europa.esig.dss.validation.DataIdentifier;

import java.util.List;

/**
 * This class describes the scope of the signature
 */
public abstract class SignatureScope implements IdentifierBasedObject {

	/**
	 * The name of the item on which this signature scope applies
	 */
	private final String name;
	
	/**
	 * Digest of the original signer data
	 */
	private final Digest dataDigest;
	
	private DataIdentifier dssId;
	
	protected SignatureScope(final String name, final Digest digest) {
		this.name = name;
		this.dataDigest = digest;
	}

	public String getName() {
		return name;
	}
	
	public Digest getDigest() {
		return dataDigest;
	}

	public abstract String getDescription();
	
	public List<String> getTransformations() {
		// not implemented by default
		return null;
	}

	public abstract SignatureScopeType getType();
	
	public DataIdentifier getDSSId() {
		if (dssId != null) {
			return dssId;
		}
		String uniqueString = name + dataDigest.toString();
		dssId = new DataIdentifier(uniqueString.getBytes());
		return dssId;
	}
	
	public String getDSSIdAsString() {
		return getDSSId().asXmlId();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if ((obj == null) || !(obj instanceof SignatureScope)) {
			return false;
		}
		SignatureScope s = (SignatureScope) obj;
		return getDSSId().equals(s.getDSSId());
	}

	@Override
	public int hashCode() {
		return getDSSId().hashCode();
	}

}
