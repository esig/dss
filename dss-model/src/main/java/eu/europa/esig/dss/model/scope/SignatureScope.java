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
package eu.europa.esig.dss.model.scope;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.identifier.IdentifierBasedObject;
import eu.europa.esig.dss.model.identifier.DataIdentifier;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * This class describes the scope of the signature
 *
 */
public abstract class SignatureScope implements IdentifierBasedObject, Serializable {

	private static final long serialVersionUID = -5579782848203348145L;

	/**
	 * The name of the item on which this signature scope applies
	 */
	private final String name;
	
	/**
	 * Original signer data
	 */
	private final DSSDocument document;
	
	/**
	 * Represents a default DSS Identifier
	 */
	private DataIdentifier dssId;
	
	/**
	 * Represents a list of dependent signature scopes (e.g. Manifest entries)
	 */
	private List<SignatureScope> children;

	/**
	 * Default constructor
	 *
	 * @param document {@link DSSDocument}
	 */
	protected SignatureScope(final DSSDocument document) {
		this(document.getName(), document);
	}

	/**
	 * Default constructor with name provided
	 *
	 * @param name {@link String} document name
	 * @param document {@link DSSDocument}
	 */
	protected SignatureScope(final String name, final DSSDocument document) {
		this.name = name;
		this.document = document;
	}

	/**
	 * Gets name of the document
	 *
	 * @return {@link String}
	 */
	public String getDocumentName() {
		return name;
	}

	/**
	 * Returns a signature scope name
	 *
	 * @param tokenIdentifierProvider {@link TokenIdentifierProvider} to extract a token identifier, when required
	 * @return {@link String}
	 */
	public String getName(TokenIdentifierProvider tokenIdentifierProvider) {
		return getDocumentName();
	}
	
	/**
	 * Gets digests of the document
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 * @return {@link Digest}
	 */
	public Digest getDigest(DigestAlgorithm digestAlgorithm) {
		if (document != null) {
			if (document instanceof DigestDocument) {
				return ((DigestDocument) document).getExistingDigest();
			} else {
				return new Digest(digestAlgorithm, Base64.getDecoder().decode(document.getDigest(digestAlgorithm)));
			}
		}
		return null;
	}

	/**
	 * Gets the signature scope description
	 *
	 * @param tokenIdentifierProvider {@link TokenIdentifierProvider} to extract a token identifier, when required
	 * @return {@link String}
	 */
	public abstract String getDescription(TokenIdentifierProvider tokenIdentifierProvider);
	
	/**
	 * Returns a list of transformations on the original document when applicable
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getTransformations() {
		// not implemented by default
		return null;
	}

	/**
	 * Returns type of the signature scope
	 *
	 * @return {@link SignatureScopeType}
	 */
	public abstract SignatureScopeType getType();
	
	/**
	 * Returns a list of dependent signature scopes (e.g. Manifest entries)
	 *
	 * @return a list of {@link SignatureScope}s
	 */
	public List<SignatureScope> getChildren() {
		if (children == null) {
			children = new ArrayList<>();
		}
		return children;
	}

	/**
	 * Adds a new child {@code SignatureScope}
	 *
	 * @param signatureScope {@link SignatureScope} to add
	 */
	public void addChildSignatureScope(SignatureScope signatureScope) {
		getChildren().add(signatureScope);
	}

	/**
	 * Returns the unique DSS Identifier
	 *
	 * @return {@link DataIdentifier}
	 */
	public DataIdentifier getDSSId() {
		if (dssId != null) {
			return dssId;
		}
		String uniqueString = name + getDigest(DigestAlgorithm.SHA256);
		dssId = new DataIdentifier(uniqueString.getBytes());
		return dssId;
	}
	
	/**
	 * Returns a {@code String} representation of the DSS Identifier
	 *
	 * @return {@link String}
	 */
	public String getDSSIdAsString() {
		return getDSSId().asXmlId();
	}

	@Override
	public String toString() {
		return "SignatureScope{" +
				"name='" + name + '\'' +
				", document=" + document +
				", dssId=" + dssId +
				", children=" + children +
				'}';
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof SignatureScope)) {
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
