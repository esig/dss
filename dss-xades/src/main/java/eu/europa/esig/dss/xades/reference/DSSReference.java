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
package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.xades.DSSObject;

import java.io.Serializable;
import java.util.List;

/**
 * Defines a ds:Reference element to be built
 */
public class DSSReference implements Serializable {

	private static final long serialVersionUID = 1121091037126466008L;

	/** The Id attribute of the reference */
	private String id;

	/** The URI attribute of the reference */
	private String uri;

	/** Defines whether the URI shall be encoded as a document name (FALSE by default) */
	private boolean encodeDocumentName = false;

	/** The Type attribute of the reference */
	private String type;

	/** The DigestAlgorithm of the reference to compute digest value */
	private DigestAlgorithm digestMethod = DigestAlgorithm.SHA512;

	/** The referenced data */
	private DSSDocument contents;

	/** List of transforms to be performed */
	private List<DSSTransform> transforms;

	/** When set, defines the ds:Object element to be incorporated within the signature */
	private DSSObject object;

	/**
	 * The default constructor
	 */
	public DSSReference() {
		// empty
	}

	/**
	 * Gets Id attribute of the reference
	 *
	 * @return {@link String}
	 */
	public String getId() {
		return id;
	}

	/**
	 * Sets Id attribute of the reference
	 *
	 * @param id {@link String}
	 */
	public void setId(String id) {
		this.id = id;
	}

	/**
	 * Gets URI attribute of the reference
	 *
	 * @return {@link String}
	 */
	public String getUri() {
		return uri;
	}

	/**
	 * Sets URI attribute of the reference
	 *
	 * @param uri {@link String}
	 */
	public void setUri(String uri) {
		this.uri = uri;
	}

	/**
	 * Gets whether the URI shall be encoded as a document name
	 *
	 * @return TRUE if the URI shall be encoded as a document name, FALSE if as a URI reference
	 */
	public boolean isEncodeDocumentName() {
		return encodeDocumentName;
	}

	/**
	 * Sets whether the URI shall be encoded as a document name.
	 * When enabled, all special characters of the URI, including '#' and '?', are considered as a part
	 * of the document name and are percent-encoded (e.g. "doc#1.xml" results in "doc%231.xml").
	 * When disabled, the URI is encoded as a URI reference according to RFC 3986, preserving
	 * the fragment and query components (e.g. "doc.xml#sig" refers to an element with Id "sig" within "doc.xml").
	 * NOTE: Same-document references (e.g. "#id") are never encoded.
	 * Default : FALSE (encode as a URI reference). The references created by DSS from the names
	 * of the signed documents (e.g. for a detached signature) have the value set to TRUE.
	 *
	 * @param encodeDocumentName whether the URI shall be encoded as a document name
	 */
	public void setEncodeDocumentName(boolean encodeDocumentName) {
		this.encodeDocumentName = encodeDocumentName;
	}

	/**
	 * Gets Type attribute of the reference
	 *
	 * @return {@link String}
	 */
	public String getType() {
		return type;
	}

	/**
	 * Sets Type attribute of the reference
	 *
	 * @param type {@link String}
	 */
	public void setType(String type) {
		this.type = type;
	}

	/**
	 * Gets DigestAlgorithm to use for digest value computation
	 *
	 * @return {@link DigestAlgorithm}
	 */
	public DigestAlgorithm getDigestMethodAlgorithm() {
		return digestMethod;
	}

	/**
	 * Sets DigestAlgorithm to use for digest value computation
	 * Default : DigestAlgorithm.SHA256
	 *
	 * @param digestMethod {@link DigestAlgorithm}
	 */
	public void setDigestMethodAlgorithm(DigestAlgorithm digestMethod) {
		this.digestMethod = digestMethod;
	}

	/**
	 * Gets a list of transforms to perform
	 *
	 * @return a list of {@link DSSTransform}s
	 */
	public List<DSSTransform> getTransforms() {
		return transforms;
	}

	/**
	 * Sets a list of transforms to perform
	 *
	 * @param transforms a list of {@link DSSTransform}s
	 */
	public void setTransforms(List<DSSTransform> transforms) {
		this.transforms = transforms;
	}

	/**
	 * Gets the original referenced document content
	 *
	 * @return {@link DSSDocument}
	 */
	public DSSDocument getContents() {
		return contents;
	}

	/**
	 * Sets the original referenced document content
	 *
	 * @param contents {@link DSSDocument}
	 */
	public void setContents(DSSDocument contents) {
		this.contents = contents;
	}

	/**
	 * Gets ds:Object element's structure to be incorporated within the signature
	 *
	 * @return {@link DSSObject}
	 */
	public DSSObject getObject() {
		return object;
	}

	/**
	 * Sets the pre-defined ds:Object element to be incorporated within the signature.
	 *
	 * NOTE : if not set, the basic ds:Object creation will be proceeded, when required
	 *
	 * @param object {@link DSSObject}
	 */
	public void setObject(DSSObject object) {
		this.object = object;
	}

	@Override
	public String toString() {
		return "DSSReference{" + "id='" + id + '\'' + ", uri='" + uri + '\'' +
				", encodeDocumentName=" + encodeDocumentName + ", type='" + type + '\'' +
				", digestMethod=" + digestMethod + ", contents=" + contents + ", transforms=" + transforms +
				", object=" + object + '}';
	}

}
