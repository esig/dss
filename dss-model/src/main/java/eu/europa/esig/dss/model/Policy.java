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
 * This class allows defining the signature policy.
 *
 */
public class Policy implements Serializable {

	private static final long serialVersionUID = 2792220193195511748L;

	/** The Id of the SignaturePolicy */
	private String id;

	/** Qualifier attribute for XAdES Identifier */
	private ObjectIdentifierQualifier qualifier;

	/** The SignaturePolicy description */
	private String description;
	
	/** The array of documentation references (used in XAdES/JAdES) */
	private String[] documentationReferences;

	/** The digest algorithm used to compute the digest */
	private DigestAlgorithm digestAlgorithm;

	/** The computed digest value */
	private byte[] digestValue;

	/** The SignaturePolicy URI qualifier */
	private String spUri;

	/** The SignaturePolicy UserNotice qualifier */
	private UserNotice userNotice;

	/** The SignaturePolicy Document Specification qualifier */
	private SpDocSpecification spDocSpecification;

	/**
	 * This property is used only in JAdES, to indicate that the digest of the signature policy document
	 * has been computed as specified in a technical specification
	 */
	private boolean hashAsInTechnicalSpecification;

	/**
	 * Empty constructor
	 */
	public Policy() {
		// empty
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
	 * Set the identifier qualifier (used in XAdES only)
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
	 * Get the SP URI (signature policy URI) qualifier
	 *
	 * @return the signature policy URI
	 */
	public String getSpuri() {
		return spUri;
	}

	/**
	 * Set the SP URI (signature policy URI) qualifier
	 *
	 * @param spUri
	 *            the signature policy URI
	 */
	public void setSpuri(String spUri) {
		this.spUri = spUri;
	}

	/**
	 * Gets the SP UserNotice qualifier
	 *
	 * @return {@link UserNotice}
	 */
	public UserNotice getUserNotice() {
		return userNotice;
	}

	/**
	 * Sets the SP UserNotice qualifier
	 *
	 * @param userNotice {@link UserNotice}
	 */
	public void setUserNotice(UserNotice userNotice) {
		this.userNotice = userNotice;
	}

	/**
	 * Gets the SP Document Specification qualifier
	 *
	 * @return {@link SpDocSpecification}
	 */
	public SpDocSpecification getSpDocSpecification() {
		return spDocSpecification;
	}

	/**
	 * Sets the SP Document Specification qualifier identifying the technical specification
	 * that defines the syntax used for producing the signature policy.
	 *
	 * @param spDocSpecification {@link SpDocSpecification}
	 */
	public void setSpDocSpecification(SpDocSpecification spDocSpecification) {
		this.spDocSpecification = spDocSpecification;
	}

	/**
	 * Gets if the digests of the signature policy has been computed as in a technical specification
	 *
	 * @return TRUE if the digests has been computed as in a technical specification, FALSE otherwise
	 */
	public boolean isHashAsInTechnicalSpecification() {
		return hashAsInTechnicalSpecification;
	}

	/**
	 * Sets if the digests of the signature policy has been computed as in a technical specification.
	 * If the property is set to FALSE, digest of the signature policy is computed in a default way (on the policy file).
	 *
	 * NOTE: The property is used only in JAdES
	 *
	 * Use method {@code setSpDocSpecification(SpDocSpecification)} to provide the technical specification
	 *
	 * @param hashAsInTechnicalSpecification if the digests has been computed as in a technical specification
	 */
	public void setHashAsInTechnicalSpecification(boolean hashAsInTechnicalSpecification) {
		this.hashAsInTechnicalSpecification = hashAsInTechnicalSpecification;
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
		if (spUri != null && !spUri.isEmpty()) {
			return false;
		}
		if (userNotice != null && !userNotice.isEmpty()) {
			return false;
		}
		if (spDocSpecification != null && spDocSpecification.getId() != null && !spDocSpecification.getId().isEmpty()) {
			return false;
		}
		if (hashAsInTechnicalSpecification) {
			return false;
		}
		return true;
	}

	/**
	 * This method checks if there is a definition at least for one signature policy qualifier
	 *
	 * @return TRUE if there is a qualifier within the signature policy, FALSE otherwise
	 */
	public boolean isSPQualifierPresent() {
		if (spUri != null && !spUri.isEmpty()) {
			return true;
		}
		if (userNotice != null && !userNotice.isEmpty()) {
			return true;
		}
		if (spDocSpecification != null && spDocSpecification.getId() != null && !spDocSpecification.getId().isEmpty()) {
			return true;
		}
		return false;
	}

	@Override
	public int hashCode() {
		int result = id != null ? id.hashCode() : 0;
		result = 31 * result + (qualifier != null ? qualifier.hashCode() : 0);
		result = 31 * result + (description != null ? description.hashCode() : 0);
		result = 31 * result + Arrays.hashCode(documentationReferences);
		result = 31 * result + (digestAlgorithm != null ? digestAlgorithm.hashCode() : 0);
		result = 31 * result + Arrays.hashCode(digestValue);
		result = 31 * result + (spUri != null ? spUri.hashCode() : 0);
		result = 31 * result + (userNotice != null ? userNotice.hashCode() : 0);
		result = 31 * result + (spDocSpecification != null ? spDocSpecification.hashCode() : 0);
		result = 31 * result + (hashAsInTechnicalSpecification ? 1 : 0);
		return result;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof Policy)) return false;

		Policy policy = (Policy) o;

		if (hashAsInTechnicalSpecification != policy.hashAsInTechnicalSpecification) return false;
		if (!Objects.equals(id, policy.id)) return false;
		if (qualifier != policy.qualifier) return false;
		if (!Objects.equals(description, policy.description)) return false;
		// Probably incorrect - comparing Object[] arrays with Arrays.equals
		if (!Arrays.equals(documentationReferences, policy.documentationReferences)) return false;
		if (digestAlgorithm != policy.digestAlgorithm) return false;
		if (!Arrays.equals(digestValue, policy.digestValue)) return false;
		if (!Objects.equals(spUri, policy.spUri)) return false;
		if (!Objects.equals(userNotice, policy.userNotice)) return false;
		return Objects.equals(spDocSpecification, policy.spDocSpecification);
	}

	@Override
	public String toString() {
		return "Policy {id='" + id + "', qualifier=" + qualifier + ", description='" + description +
				"', documentationReferences=" + Arrays.toString(documentationReferences) +
				", digestAlgorithm=" + digestAlgorithm + ", digestValue=" + Arrays.toString(digestValue) +
				", spUri='" + spUri + "', userNotice=" + userNotice + ", spDocSpecification='" + spDocSpecification +
				"', hashAsInTechnicalSpecification=" + hashAsInTechnicalSpecification + "}";
	}

}
