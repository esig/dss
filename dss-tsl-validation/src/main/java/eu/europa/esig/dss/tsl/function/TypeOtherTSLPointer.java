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
package eu.europa.esig.dss.tsl.function;

import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;

import java.util.Map;
import java.util.Objects;

/**
 * Allows TSL filtering by TSLType
 *
 */
public class TypeOtherTSLPointer extends AbstractOtherTSLPointerPredicate {

	/** The TSLType property */
	private static final String EXPECTED_TAG_NAME = "{http://uri.etsi.org/02231/v2#}TSLType";

	/** The expected TSLType */
	private final String expectedTSLType;

	/**
	 * Default constructor
	 *
	 * @param expectedTSLType {@link String} the TSLType value to filter by
	 */
	public TypeOtherTSLPointer(String expectedTSLType) {
		Objects.requireNonNull(expectedTSLType, "Expected TSLType must be defined");
		this.expectedTSLType = expectedTSLType;
	}

	@Override
	public boolean test(OtherTSLPointerType o) {
		Map<String, Object> extractAdditionalInformation = extractAdditionalInformation(o);
		String tslType = (String) extractAdditionalInformation.get(EXPECTED_TAG_NAME);
		return expectedTSLType.equalsIgnoreCase(tslType);
	}

}
