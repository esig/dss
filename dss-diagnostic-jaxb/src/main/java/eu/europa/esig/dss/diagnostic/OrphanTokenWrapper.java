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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanToken;

import java.util.Objects;

/**
 * Represents a wrapper class for an XML orphan token
 *
 */
public abstract class OrphanTokenWrapper<T extends XmlOrphanToken> {

	/** Xml orphan token */
	protected final T orphanToken;

	/**
	 * Default constructor
	 *
	 * @param orphanToken {@link T}
	 */
	protected OrphanTokenWrapper(final T orphanToken) {
		Objects.requireNonNull(orphanToken, "XmlOrphanToken cannot be null!");
		this.orphanToken = orphanToken;
	}
	
	/**
	 * Returns identifier of the orphan token
	 * 
	 * @return {@link String} id
	 */
	public String getId() {
		return orphanToken.getId();
	}
	
	/**
	 * Returns base64-encoded byte array of the token
	 * 
	 * @return byte array
	 */
	public abstract byte[] getBinaries();

	/**
	 * Returns digest of the token
	 * 
	 * @return {@link XmlDigestAlgoAndValue}
	 */
	public abstract XmlDigestAlgoAndValue getDigestAlgoAndValue();
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((orphanToken == null) ? 0 : orphanToken.getId().hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof OrphanTokenWrapper))
			return false;
		OrphanTokenWrapper other = (OrphanTokenWrapper) obj;
		if (getId() == null) {
			if (other.getId() != null) {
				return false;
			}
		} else if (!getId().equals(other.getId())) {
			return false;
		}
		return true;
	}
	
	@Override
	public String toString() {
		return "OrphanTokenWrapper Class='" + getClass() + "', Id='" + getId() + "'";
	}

}
