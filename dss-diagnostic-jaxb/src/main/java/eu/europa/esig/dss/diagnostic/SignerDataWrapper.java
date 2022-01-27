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
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;

/**
 * Wraps the {@code XmlSignerData}
 *
 */
public class SignerDataWrapper {
	
	/** Wrapped Signed data */
	private final XmlSignerData signerData;
	
	/**
	 * Default constructor
	 *
	 * @param signerData {@link XmlSignerData}
	 */
	public SignerDataWrapper(final XmlSignerData signerData) {
		this.signerData = signerData;
	}
	
	/**
	 * Gets identifier of the signer data
	 *
	 * @return {@link String}
	 */
	public String getId() {
		return signerData.getId();
	}
	
	/**
	 * Gets referenced name of the signer data
	 *
	 * @return {@link String}
	 */
	public String getReferencedName() {
		return signerData.getReferencedName();
	}
	
	/**
	 * Gets digest algo and value of the signer data
	 *
	 * @return {@link XmlDigestAlgoAndValue}
	 */
	public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
		return signerData.getDigestAlgoAndValue();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((getId() == null) ? 0 : getId().hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SignerDataWrapper other = (SignerDataWrapper) obj;
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
		return "SignerData Id='" + getId() + "'";
	}

}
