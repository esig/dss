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

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.validation.scope.SignatureScope;

/**
 * XPointer signature scope
 */
public class XPointerSignatureScope extends SignatureScope {

	/**
	 * XPointer query
	 */
	private final String uri;

	/**
	 * Default constructor
	 *
	 * @param xmlId {@link String} id of the reference element
	 * @param uri {@link String}
	 * @param digest {@link Digest}
	 */
	protected XPointerSignatureScope(final String xmlId, final String uri, final Digest digest) {
		super(xmlId, digest);
		this.uri = uri;
	}

	@Override
	public String getDescription() {
		StringBuilder sb = new StringBuilder("The XML element with ID '");
		sb.append(getName());
		sb.append("' is an XPointer query (uri: '");
		sb.append(uri);
		sb.append("').");
		return sb.toString();
	}

	@Override
	public SignatureScopeType getType() {
		return SignatureScopeType.PARTIAL;
	}

}
