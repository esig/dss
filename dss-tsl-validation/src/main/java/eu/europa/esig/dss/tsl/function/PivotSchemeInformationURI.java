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
package eu.europa.esig.dss.tsl.function;

import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIType;

import java.util.function.Predicate;

/**
 * The Pivot scheme information URI filter predicate
 * 
 */
public final class PivotSchemeInformationURI implements Predicate<NonEmptyMultiLangURIType> {

	/**
	 * Defined condition in (draft) ETSI TS 119 615
	 */
	private static final String PIVOT_SUFFIX = ".xml";

	@Override
	public boolean test(NonEmptyMultiLangURIType t) {
		if (t != null && t.getValue() != null) {
			return t.getValue().endsWith(PIVOT_SUFFIX);
		}
		return false;
	}

}
