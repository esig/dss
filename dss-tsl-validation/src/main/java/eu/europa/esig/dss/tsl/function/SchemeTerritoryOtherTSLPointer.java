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

import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

/**
 * The predicate is used to filter certain TLs by the accepted country codes
 *
 */
public class SchemeTerritoryOtherTSLPointer extends AbstractOtherTSLPointerPredicate {

	/** The element name containing the country code */
	private static final String EXPECTED_TAG_NAME = "{http://uri.etsi.org/02231/v2#}SchemeTerritory";

	/** A collection of country codes to be accepted */
	private final Collection<String> countryCodes;

	/**
	 * Constructor allowing to filter a single country code
	 *
	 * @param countryCode {@link String} country code to be loaded
	 */
	public SchemeTerritoryOtherTSLPointer(String countryCode) {
		this(Collections.singleton(countryCode));
	}

	/**
	 * Constructor allowing to filter a collection of country coded
	 *
	 * @param countryCodes a collection of {@link String}s country codes to be loaded
	 */
	public SchemeTerritoryOtherTSLPointer(Collection<String> countryCodes) {
		this.countryCodes = countryCodes;
	}

	@Override
	public boolean test(OtherTSLPointerType o) {
		Map<String, Object> extractAdditionalInformation = extractAdditionalInformation(o);
		String schemeTerritory = (String) extractAdditionalInformation.get(EXPECTED_TAG_NAME);
		return countryCodes.contains(schemeTerritory);
	}

}
