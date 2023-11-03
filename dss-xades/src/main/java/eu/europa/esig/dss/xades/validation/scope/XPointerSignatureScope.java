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
package eu.europa.esig.dss.xades.validation.scope;

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.validation.scope.SignatureScopeWithTransformations;

import java.util.List;
import java.util.Objects;

/**
 * XPointer signature scope
 */
public class XPointerSignatureScope extends SignatureScopeWithTransformations {

	private static final long serialVersionUID = 203530674533107438L;

	/**
	 * XPointer query
	 */
	private final String uri;

	/**
	 * Default constructor
	 *
	 * @param uri {@link String}
	 * @param document {@link DSSDocument}
	 * @param transformations a list of {@link String} transform descriptions
	 */
	protected XPointerSignatureScope(final String uri, final DSSDocument document, final List<String> transformations) {
		super(getDocumentNameFromXPointer(uri), document, transformations);
		this.uri = uri;
	}

	private static String getDocumentNameFromXPointer(String uri) {
		return DomUtils.isRootXPointer(uri) ? "Full XML file" : DomUtils.getXPointerId(uri);
	}

	@Override
	public String getDescription(TokenIdentifierProvider tokenIdentifierProvider) {
		StringBuilder sb = new StringBuilder("XPointer query to ");
		if (DomUtils.isRootXPointer(uri)) {
			sb.append("root XML element");
		} else {
			sb.append("element with Id '");
			sb.append(getDocumentName());
			sb.append("'");
		}
		return addTransformationIfNeeded(sb.toString());
	}

	@Override
	public SignatureScopeType getType() {
		return DomUtils.isRootXPointer(uri) ? SignatureScopeType.FULL : SignatureScopeType.PARTIAL;
	}

	@Override
	public String toString() {
		return "XPointerSignatureScope{" +
				"uri='" + uri + '\'' +
				"} " + super.toString();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof XPointerSignatureScope)) return false;
		if (!super.equals(o)) return false;

		XPointerSignatureScope that = (XPointerSignatureScope) o;

		return Objects.equals(uri, that.uri);
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = 31 * result + (uri != null ? uri.hashCode() : 0);
		return result;
	}

}
