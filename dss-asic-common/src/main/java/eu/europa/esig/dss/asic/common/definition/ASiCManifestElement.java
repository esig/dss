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
package eu.europa.esig.dss.asic.common.definition;

import eu.europa.esig.dss.xml.common.definition.DSSElement;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;

/**
 * ASiC XSD elements
 */
public enum ASiCManifestElement implements DSSElement {

	/** XAdESSignatures */
	XADES_SIGNATURES("XAdESSignatures"),

	/** ASiCManifest */
	ASIC_MANIFEST("ASiCManifest"),

	/** SigReference */
	SIG_REFERENCE("SigReference"),
	
	/** Extension */
	EXTENSION("Extension"),

	/** DataObjectReference */
	DATA_OBJECT_REFERENCE("DataObjectReference"),
	
	/** ASiCManifestExtensions */
	ASIC_MANIFEST_EXTENSIONS("ASiCManifestExtensions"),
	
	/** DataObjectReferenceExtensions */
	DATA_OBJECT_REFERENCE_EXTENSIONS("DataObjectReferenceExtensions");

	/** Namespace */
	private final DSSNamespace namespace;

	/** The tag name */
	private final String tagName;

	/**
	 * Default constructor
	 *
	 * @param tagName {@link String}
	 */
	ASiCManifestElement(String tagName) {
		this.tagName = tagName;
		this.namespace = ASiCManifestNamespace.NS;
	}

	@Override
	public DSSNamespace getNamespace() {
		return namespace;
	}

	@Override
	public String getTagName() {
		return tagName;
	}

	@Override
	public String getURI() {
		return namespace.getUri();
	}

	@Override
	public boolean isSameTagName(String value) {
		return tagName.equals(value);
	}

}
