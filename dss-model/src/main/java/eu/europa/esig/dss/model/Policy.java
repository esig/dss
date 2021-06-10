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
package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

/**
 * This class allows to define the signature policy.
 */
public class Policy implements Serializable {

	private static final long serialVersionUID = 2792220193195511748L;

	/** The Id of the SignaturePolicy */
	private String id;

	/** Qualifier attribute for XAdES Identifier */
	private ObjectIdentifierQualifier qualifier;

	/** The SignaturePolicy description */
	private String description;
	
	/** The array of documentation references (used in XAdES) */
	private String[] documentationReferences;

	/** The digest algorithm used to compute the digest */
	private DigestAlgorithm digestAlgorithm;

	/** The computed digest value */
	private byte[] digestValue;

	/** The SignaturePolicy URI */
	private String spuri;

	/**
	 * Empty constructor
	 */
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
	public ObjectIdentifierQualifier getQualifier() {
		return qualifier;
	}

	/**
	 * Set the identifier qualifier
	 *
	 * @param qualifier
	 *            the qualifier
	 */
	public void setQualifier(ObjectIdentifierQualifier qualifier) {
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
	 * Get the signature policy documentation references
	 *
	 * @return the signature policy documentation references
	 */
	public String[] getDocumentationReferences() {
		return documentationReferences;
	}

	/**
	 * Set a list of signature documentation references
	 * 
	 * @param documentationReferences
	 *            an array of {@link String} documentation references
	 */
	public void setDocumentationReferences(String... documentationReferences) {
		this.documentationReferences = documentationReferences;
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
	
	/**
	 * Checks if the object's data is not filled
	 * 
	 * @return TRUE if the Policy object does not have filled data, FALSE otherwise
	 */
	public boolean isEmpty() {
		if (id != null && !id.isEmpty()) {
			return false;
		}
		if (qualifier != null) {
			return false;
		}
		if (description != null && !description.isEmpty()) {
			return false;
		}
		if (documentationReferences != null && documentationReferences.length != 0) {
			return false;
		}
		if (digestAlgorithm != null) {
			return false;
		}
		if (digestValue != null && digestValue.length != 0) {
			return false;
		}
		if (spuri != null && !spuri.isEmpty()) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((description == null) ? 0 : description.hashCode());
		result = (prime * result) + ((documentationReferences == null) ? 0 : Arrays.hashCode(documentationReferences));
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
		if (!Objects.equals(description, other.description)) {
			return false;
		}
		if (documentationReferences == null) {
			if (other.documentationReferences != null) {
				return false;
			}
		} else if (!Arrays.equals(documentationReferences, other.documentationReferences)) {
			return false;
		}
		if (digestAlgorithm != other.digestAlgorithm) {
			return false;
		}
		if (!Arrays.equals(digestValue, other.digestValue)) {
			return false;
		}
		if (!Objects.equals(id, other.id)) {
			return false;
		}
		if (!Objects.equals(spuri, other.spuri)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "Policy [id=" + id + ", description=" + description + ", digestAlgorithm=" + digestAlgorithm + ", digestValue=" + Arrays.toString(digestValue)
				+ ", spuri=" + spuri + ", documentationReferences=" + Arrays.toString(documentationReferences) + "]";
	}

}
