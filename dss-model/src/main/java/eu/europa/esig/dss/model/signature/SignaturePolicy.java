/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.model.signature;

import eu.europa.esig.dss.enumerations.SignaturePolicyType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.UserNotice;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;

/**
 * Represents the values of a SignaturePolicy extracted on a signature validation
 *
 */
public class SignaturePolicy implements Serializable {

	private static final long serialVersionUID = -7123856626729507608L;

	/** The signature policy identifier */
	private final String identifier;

	/** The policy description */
	private String description;

	/** The documentation references */
	private List<String> documentationReferences;

	/** The policy content document */
	private DSSDocument policyContent;

	/** The digest of the signature policy */
	private Digest digest;

	/**
	 * This indicated should the hash be computed as specified in a relevant signature specification
	 * according to the signature policy format
	 */
	private boolean hashAsInTechnicalSpecification;

	/** If it is a zero-hash policy */
	private boolean zeroHash;

	/**
	 * Signature Policy URI qualifier
	 * A URL where a copy of the signature policy MAY be obtained;
	 */
	private String uri;

	/**
	 * Signature Policy User Notice qualifier
	 * User notice that should be displayed when the signature is verified.
	 */
	private UserNotice userNotice;

	/**
	 * Signature Policy Document Specification qualifier
	 * An identifier of the technical specification that defines the syntax used for producing
	 * the signature policy document.
	 */
	private SpDocSpecification docSpecification;

	/**
	 * Validation result of the current signature policy
	 */
	private SignaturePolicyValidationResult validationResult;

	/**
	 * The default constructor for SignaturePolicy. It represents the implied policy.
	 */
	public SignaturePolicy() {
		this.identifier = SignaturePolicyType.IMPLICIT_POLICY.name();
	}

	/**
	 * The default constructor for SignaturePolicy.
	 *
	 * @param identifier
	 *            the policy identifier
	 */
	public SignaturePolicy(final String identifier) {
		this.identifier = identifier;
	}

	/**
	 * Returns the signature policy identifier
	 * 
	 * @return the signature policy identifier
	 */
	public String getIdentifier() {
		return identifier;
	}

	/**
	 * Gets description
	 *
	 * @return {@link String}
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Sets description (*optional)
	 *
	 * @param description {@link String}
	 */
	public void setDescription(final String description) {
		this.description = description;
	}

	/**
	 * Returns a DSSDocument with the signature policy content
	 *
	 * @return a DSSDocument which contains the signature policy
	 */
	public DSSDocument getPolicyContent() {
		return policyContent;
	}

	/**
	 * Sets policy document content
	 *
	 * @param policyContent {@link DSSDocument}
	 */
	public void setPolicyContent(DSSDocument policyContent) {
		this.policyContent = policyContent;
	}

	/**
	 * Gets the {@code Digest}
	 *
	 * @return {@link Digest}
	 */
	public Digest getDigest() {
		return digest;
	}

	/**
	 * Sets the {@code Digest}
	 *
	 * @param digest {@link Digest}
	 */
	public void setDigest(Digest digest) {
		this.digest = digest;
	}

	/**
	 * Gets the documentation references
	 * NOTE: optional, used in XAdES
	 *
	 * @return a list of {@link String} documentation references
	 */
	public List<String> getDocumentationReferences() {
		return documentationReferences;
	}

	/**
	 * Sets the documentation references
	 *
	 * @param documentationReferences a list of {@link String} documentation references
	 */
	public void setDocumentationReferences(List<String> documentationReferences) {
		this.documentationReferences = documentationReferences;
	}
	
	/**
	 * Gets a list of Strings describing the 'ds:Transforms' element
	 * NOTE: XAdES only
	 *
	 * @return a description of 'ds:Transforms' if present, null otherwise
	 */
	public List<String> getTransformsDescription() {
		// not applicable by default
		return Collections.emptyList();
	}
	
	/**
	 * Gets if the policy is a zero-hash (no hash check shall be performed)
	 *
	 * @return TRUE if the policy is a zero-hash, FALSE otherwise
	 */
	public boolean isZeroHash() {
		return zeroHash;
	}

	/**
	 * Sets if the policy is a zero-hash (no hash check shall be performed)
	 *
	 * @param zeroHash if the policy is a zero-hash
	 */
	public void setZeroHash(boolean zeroHash) {
		this.zeroHash = zeroHash;
	}

	/**
	 * Gets if the digest should be computed as specified in the relevant technical specification
	 *
	 * @return TRUE if the digest should be computed as specified in the relevant technical specification, FALSE otherwise
	 */
	public boolean isHashAsInTechnicalSpecification() {
		return hashAsInTechnicalSpecification;
	}

	/**
	 * Sets should the digest be computed as specified in a corresponding technical specification
	 *
	 * @param hashAsInTechnicalSpecification should the digest be computed as in technical specification
	 */
	public void setHashAsInTechnicalSpecification(boolean hashAsInTechnicalSpecification) {
		this.hashAsInTechnicalSpecification = hashAsInTechnicalSpecification;
	}

	/**
	 * Returns the signature policy URI (if found)
	 *
	 * @return the URI of the signature policy (or null if not available information)
	 */
	public String getUri() {
		return uri;
	}

	/**
	 * Sets the signature policy URI
	 *
	 * @param uri signature policy URI
	 */
	public void setUri(final String uri) {
		this.uri = uri;
	}

	/**
	 * Gets user notice that should be displayed when the signature is verified
	 *
	 * @return {@link String}
	 */
	public UserNotice getUserNotice() {
		return userNotice;
	}

	/**
	 * Sets user notice that should be displayed when the signature is verified
	 *
	 * @param userNotice {@link UserNotice} user notice
	 */
	public void setUserNotice(final UserNotice userNotice) {
		this.userNotice = userNotice;
	}

	/**
	 * Gets the Document Specification Qualifier when present
	 *
	 * @return {@link SpDocSpecification}
	 */
	public SpDocSpecification getDocSpecification() {
		return docSpecification;
	}

	/**
	 * Sets the Document Specification qualifier
	 *
	 * @param docSpecification {@link SpDocSpecification}
	 */
	public void setDocSpecification(SpDocSpecification docSpecification) {
		this.docSpecification = docSpecification;
	}


	/**
	 * Gets validation result of the signature policy
	 *
	 * @return {@link SignaturePolicyValidationResult}
	 */
	public SignaturePolicyValidationResult getValidationResult() {
		return validationResult;
	}

	/**
	 * Sets the signature policy's validation result
	 *
	 * @param validationResult {@link SignaturePolicyValidationResult}
	 */
	public void setValidationResult(SignaturePolicyValidationResult validationResult) {
		this.validationResult = validationResult;
	}

}
