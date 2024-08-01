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

import eu.europa.esig.dss.enumerations.DigestMatcherType;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * This class is used to store individual reference validations.
 * 
 * For XAdES, that means reference tag(s) validation
 * 
 * For CAdES, that means message-digest validation
 *
 */
public class ReferenceValidation implements Serializable {

	private static final long serialVersionUID = 1303869856995695436L;

	/** The type of the Reference */
	private DigestMatcherType type;

	/** The pointed reference is found */
	private boolean found;

	/** The pointed reference is intact */
	private boolean intact;

	/** The digest value embedded in reference element */
	private Digest digest;

	/** The unique identifier of the reference. (E.g. for XAdES : reference Id attribute value) */
	private String id;

	/** The reference to the original document. (E.g. for XAdES : reference URI attribute value) */
	private String uri;

	/** Name of the matching document (when applicable) */
	private String documentName;

	/** List of used transforms to compute digest of the reference */
	protected List<String> transforms;

	/** The reference points to more than one element */
	private boolean isDuplicated;

	/**
	 * List of dependent {@code ReferenceValidation}s (used in case of manifest type
	 * for manifest entries)
	 */
	private List<ReferenceValidation> dependentReferenceValidations;

	/**
	 * Default constructor instantiating object with null values
	 */
	public ReferenceValidation() {
		// empty
	}

	/**
	 * Returns type of the validated reference
	 *
	 * @return {@link DigestMatcherType}
	 */
	public DigestMatcherType getType() {
		return type;
	}

	/**
	 * Sets type of the reference
	 *
	 * @param type {@link DigestMatcherType}
	 */
	public void setType(DigestMatcherType type) {
		this.type = type;
	}

	/**
	 * Gets if the references data has been found
	 *
	 * @return TRUE if the data was found, FALSE otherwise
	 */
	public boolean isFound() {
		return found;
	}

	/**
	 * Sets if the references data has been found
	 *
	 * @param found if the references data has been found
	 */
	public void setFound(boolean found) {
		this.found = found;
	}

	/**
	 * Gets if the digest of a referenced document matches to one defined in the reference
	 *
	 * @return TRUE if the digest value of a referenced document matches, FALSE otherwise
	 */
	public boolean isIntact() {
		return intact;
	}

	/**
	 * Sets if the digest value of a referenced document matches
	 *
	 * @param intact if the digest value of a referenced document matches
	 */
	public void setIntact(boolean intact) {
		this.intact = intact;
	}

	/**
	 * Gets the incorporated {@code Digest}
	 *
	 * @return {@link Digest}
	 */
	public Digest getDigest() {
		return digest;
	}

	/**
	 * Sets the reference's {@code Digest}
	 *
	 * @param digest {@link Digest}
	 */
	public void setDigest(Digest digest) {
		this.digest = digest;
	}

	/**
	 * Gets the unique identifier of a reference. (E.g. for XAdES : reference Id attribute value)
	 *
	 * @return {@link String}
	 */
	public String getId() {
		return id;
	}

	/**
	 * Sets the unique identifier of a reference. (E.g. for XAdES : reference Id attribute value)
	 *
	 * @param id {@link String}
	 */
	public void setId(String id) {
		this.id = id;
	}

	/**
	 * Gets the reference to the original document. (E.g. for XAdES : reference URI attribute value).
	 *
	 * @return {@link String}
	 */
	public String getUri() {
		return uri;
	}

	/**
	 * Sets the reference to the original document. (E.g. for XAdES : reference URI attribute value).
	 *
	 * @param uri {@link String}
	 */
	public void setUri(String uri) {
		this.uri = uri;
	}

	/**
	 * Gets matching document name
	 *
	 * @return {@link String}
	 */
	public String getDocumentName() {
		return documentName;
	}

	/**
	 * Sets the matching document name
	 *
	 * @param documentName {@link String}
	 */
	public void setDocumentName(String documentName) {
		this.documentName = documentName;
	}

	/**
	 * Returns a list of transformations contained in the {@code reference}
	 * 
	 * @return list of {@link String} transfor names
	 */
	public List<String> getTransformationNames() {
		return transforms;
	}

	/**
	 * Sets a list of transforms for the reference
	 *
	 * @param transforms list of {@link String} transform names
	 */
	public void setTransformationNames(List<String> transforms) {
		this.transforms = transforms;
	}

	/**
	 * Returns if the referenced data is ambiguous
	 *
	 * @return TRUE if the referenced data is ambiguous, FALSE otherwise
	 */
	public boolean isDuplicated() {
		return isDuplicated;
	}

	/**
	 * Sets if the referenced data is ambiguous
	 *
	 * @param isDuplicated if the referenced data is ambiguous
	 */
	public void setDuplicated(boolean isDuplicated) {
		this.isDuplicated = isDuplicated;
	}
	
	/**
	 * Returns a list of dependent validations from {@code this}
	 * Note: used to contain manifest entries
	 * 
	 * @return list of {@link ReferenceValidation}s
	 */
	public List<ReferenceValidation> getDependentValidations() {
		if (dependentReferenceValidations == null) {
			dependentReferenceValidations = new ArrayList<>();
		}
		return dependentReferenceValidations;
	}

}
