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
package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.List;

/**
 * Defines a ds:Reference element to be built
 */
public class DSSReference {

	/** The Id attribute of the reference */
	private String id;

	/** The URI attribute of the reference */
	private String uri;

	/** The Type attribute of the reference */
	private String type;

	/** The DigestAlgorithm of the reference to compute digest value */
	private DigestAlgorithm digestMethod;

	/** The referenced data */
	private DSSDocument contents;

	/** List of transforms to be performed */
	private List<DSSTransform> transforms;

	/**
	 * The default constructor
	 */
	public DSSReference() {
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

	@Override
	public String toString() {
		return "DSSReference{" + "id='" + id + '\'' + ", uri='" + uri + '\'' + ", type='" + type + '\'' + ", digestMethod='"
				+ (digestMethod != null ? digestMethod.getName() : digestMethod) + '\'' + ", contents=" + (contents != null ? contents.toString() : contents)
				+ ", transforms=" + transforms + '}';
	}
}
