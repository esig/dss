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
package eu.europa.esig.dss.pades.validation.scope;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.pades.validation.ByteRange;

import java.util.Objects;

/**
 * The signature scope represents a signed PDF byte range
 *
 */
public abstract class PdfByteRangeSignatureScope extends SignatureScope {

	private static final long serialVersionUID = -5812599751054145819L;

	/** The covered byte range */
	private final ByteRange byteRange;

	/**
	 * Default constructor
	 *
	 * @param name {@link String} document name
	 * @param byteRange {@link ByteRange}
	 * @param document {@link DSSDocument} pdf revision document
	 */
	protected PdfByteRangeSignatureScope(final String name, final ByteRange byteRange, final DSSDocument document) {
		super(name, document);
		this.byteRange = byteRange;
	}

	@Override
	public String getDescription(TokenIdentifierProvider tokenIdentifierProvider) {
		return "The document ByteRange : " + byteRange;
	}

	@Override
	public String toString() {
		return "PdfByteRangeSignatureScope{" +
				"byteRange=" + byteRange +
				"} " + super.toString();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof PdfByteRangeSignatureScope)) return false;
		if (!super.equals(o)) return false;

		PdfByteRangeSignatureScope that = (PdfByteRangeSignatureScope) o;

		return Objects.equals(byteRange, that.byteRange);
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = 31 * result + (byteRange != null ? byteRange.hashCode() : 0);
		return result;
	}

}
