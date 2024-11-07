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
 * This predicate allows filtering of TSL pointers by a MimeType
 *
 */
public class MimetypeOtherTSLPointer extends AbstractOtherTSLPointerPredicate {

	/** The MimeType tage name */
	private static final String EXPECTED_TAG_NAME = "{http://uri.etsi.org/02231/v2/additionaltypes#}MimeType";

	/** Expected MimeType */
	private final String expectedMimeType;

	/**
	 * Default constructor
	 *
	 * @param expectedMimeType {@link String} MimeType to filter by
	 */
	public MimetypeOtherTSLPointer(String expectedMimeType) {
		Objects.requireNonNull(expectedMimeType, "Expected MimeType must be defined");
		this.expectedMimeType = expectedMimeType;
	}

	@Override
	public boolean test(OtherTSLPointerType o) {
		Map<String, Object> extractAdditionalInformation = extractAdditionalInformation(o);
		String mimeType = (String) extractAdditionalInformation.get(EXPECTED_TAG_NAME);
		return expectedMimeType.equalsIgnoreCase(mimeType);
	}

}
