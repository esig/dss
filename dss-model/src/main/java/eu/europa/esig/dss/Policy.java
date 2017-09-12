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
package eu.europa.esig.dss;

import java.io.Serializable;
import java.util.Arrays;

/**
 * This class allows to define the signature policy.
 */
@SuppressWarnings("serial")
public class Policy implements Serializable {

	private String id;

	/* Qualifier attribute for XAdES Identifier */
	private String qualifier;

	private String description;

	private DigestAlgorithm digestAlgorithm;

	private byte[] digestValue;

	private String spuri;

	public Policy() {
	}

	/**
	 * Get the signature policy (EPES)
	 *
	 * @return the policy id
	 */
	public String getId() {
		return id;
	}

	/**
	 * Set the signature policy (EPES)
	 *
	 * @param id
	 *            the policy id
	 */
	public void setId(final String id) {
		this.id = id;
	}

	/**
	 * Get the identifier qualifier
	 *
	 * @return the qualifier
	 */
	public String getQualifier() {
		return qualifier;
	}

	/**
	 * Set the identifier qualifier
	 *
	 * @param qualifier
	 *            the qualifier
	 */
	public void setQualifier(String qualifier) {
		this.qualifier = qualifier;
	}

	/**
	 * Get the signature policy description
	 *
	 * @return the signature policy description
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Set the signature policy description
	 *
	 * @param description
	 *            the policy description
	 */
	public void setDescription(String description) {
		this.description = description;
	}

	/**
	 * Return the hash algorithm for the signature policy
	 *
	 * @return the used digest algorithm for the policy
	 */
	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	/**
	 * Set the hash algorithm for the explicit signature policy
	 *
	 * @param digestAlgorithm
	 *            the used digest algorithm for the policy
	 */
	public void setDigestAlgorithm(final DigestAlgorithm digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
	}

	/**
	 * Get the hash value of the explicit signature policy
	 *
	 * @return the digest value for the policy
	 */
	public byte[] getDigestValue() {
		return digestValue;
	}

	/**
	 * Set the hash value of implicit signature policy
	 *
	 * @param digestValue
	 *            the digest of the policy
	 */
	public void setDigestValue(final byte[] digestValue) {
		this.digestValue = digestValue;
	}

	/**
	 * Get the SP URI (signature policy URI)
	 *
	 * @return the signature policy URI
	 */
	public String getSpuri() {
		return spuri;
	}

	/**
	 * Set the SP URI (signature policy URI)
	 *
	 * @param spuri
	 *            the signature policy URI
	 */
	public void setSpuri(String spuri) {
		this.spuri = spuri;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((description == null) ? 0 : description.hashCode());
		result = (prime * result) + ((digestAlgorithm == null) ? 0 : digestAlgorithm.hashCode());
		result = (prime * result) + Arrays.hashCode(digestValue);
		result = (prime * result) + ((id == null) ? 0 : id.hashCode());
		result = (prime * result) + ((spuri == null) ? 0 : spuri.hashCode());
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
		Policy other = (Policy) obj;
		if (description == null) {
			if (other.description != null) {
				return false;
			}
		} else if (!description.equals(other.description)) {
			return false;
		}
		if (digestAlgorithm != other.digestAlgorithm) {
			return false;
		}
		if (!Arrays.equals(digestValue, other.digestValue)) {
			return false;
		}
		if (id == null) {
			if (other.id != null) {
				return false;
			}
		} else if (!id.equals(other.id)) {
			return false;
		}
		if (spuri == null) {
			if (other.spuri != null) {
				return false;
			}
		} else if (!spuri.equals(other.spuri)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "Policy [id=" + id + ", description=" + description + ", digestAlgorithm=" + digestAlgorithm + ", digestValue=" + Arrays.toString(digestValue)
				+ ", spuri=" + spuri + "]";
	}

}