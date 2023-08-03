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
package eu.europa.esig.xades.definition.xades141;

import eu.europa.esig.dss.jaxb.common.definition.DSSElement;
import eu.europa.esig.dss.jaxb.common.definition.DSSNamespace;
import eu.europa.esig.xades.definition.XAdESNamespaces;

/**
 * The XAdES 1.4.1 elements
 */
public enum XAdES141Element implements DSSElement {

	ARCHIVE_TIMESTAMP("ArchiveTimeStamp"),

	ATTRIBUTE_CERTIFICATE_REFS_V2("AttributeCertificateRefsV2"),

	CERT_REFS("CertRefs"),

	COMPLETE_CERTIFICATE_REFS_V2("CompleteCertificateRefsV2"),
	
	RECOMPUTED_DIGEST_VALUE("RecomputedDigestValue"),

	REFS_ONLY_TIMESTAMP_V2("RefsOnlyTimeStampV2"),

	RENEWED_DIGESTS("RenewedDigests"),

	SIG_AND_REFS_TIMESTAMP_V2("SigAndRefsTimeStampV2"),

	SIG_POL_DOC_LOCAL_URI("SigPolDocLocalURI"),

	SIGNATURE_POLICY_DOCUMENT("SignaturePolicyDocument"),

	SIGNATURE_POLICY_STORE("SignaturePolicyStore"),

	SP_DOC_SPECIFICATION("SPDocSpecification"),

	TIMESTAMP_VALIDATION_DATA("TimeStampValidationData");

	/** Namespace */
	private final DSSNamespace namespace;

	/** The tag name */
	private final String tagName;

	/**
	 * Default constructor
	 *
	 * @param tagName {@link String}
	 */
	XAdES141Element(String tagName) {
		this.tagName = tagName;
		this.namespace = XAdESNamespaces.XADES_141;
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
