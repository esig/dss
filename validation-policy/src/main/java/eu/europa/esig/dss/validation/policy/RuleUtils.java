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
package eu.europa.esig.dss.validation.policy;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.TimeConstraint;

public final class RuleUtils {

	private static final Logger logger = LoggerFactory.getLogger(RuleUtils.class);

	private RuleUtils() {
	}

	/**
	 * Converts the given time duration (value) in the given unit (fromUnit) to given unit (toUnit).
	 *
	 * @param fromUnit
	 * @param toUnit
	 * @param value
	 * @return
	 */
	public static long convertDuration(final String fromUnit, final String toUnit, long value) {
		TimeUnit fromTimeUnit = toTimeUnit(fromUnit);
		TimeUnit toTimeUnit = toTimeUnit(toUnit);
		if (fromTimeUnit != null && toTimeUnit != null) {
			return toTimeUnit.convert(value, fromTimeUnit);
		} else {
			throw new DSSException("Cannot convert duration with args (" + fromUnit + ", " + toUnit + ", " + value + ")");
		}
	}

	private static TimeUnit toTimeUnit(String timeUnitString) {
		TimeUnit result = null;
		try {
			result = TimeUnit.valueOf(timeUnitString);
		} catch (Exception e) {
			logger.warn("Cannot parse '" + timeUnitString + "' to TimeUnit");
		}
		return result;
	}

	/**
	 * This method checks if the given string is present in the list of {@code String}(s).
	 *
	 * @param id
	 *            {@code String} to check
	 * @param idList
	 *            the list of {@code String}(s)
	 * @return tru if the {@code id} is present in the {@code idList}, false otherwise
	 */
	public static boolean contains1(final String id, final List<String> idList) {

		if ((id != null) && (idList != null)) {
			for (final String idFromList : idList) {
				if (idFromList.equals(id)) {
					return true;
				}
			}
		}
		return false;
	}

	public static String canonicalizeDigestAlgo(final String algo) {

		String digestAlgo = algo.trim().replace("-", "").toUpperCase();
		return digestAlgo;
	}

	public static String canonicalizeEncryptionAlgo(final String algo) {

		String digestAlgo = algo.trim().replace("-", "").toUpperCase();
		return digestAlgo;
	}

	public static String canonicalizeSignatureAlgo(final String algo) {

		String signatureAlgo = algo.trim().replace("-", "").replace("Encryption", "").toUpperCase().replace("WITH", "with");
		return signatureAlgo;
	}

	public static boolean in(final SubIndication value, final SubIndication... values) {
		final boolean contains = Arrays.asList(values).contains(value);
		return contains;
	}

	public static String toString(List<String> strings) {

		final String SEPARATOR = ",";
		final StringBuilder stringBuilder = new StringBuilder();
		for (final String string : strings) {

			if (stringBuilder.length() != 0) {

				stringBuilder.append(SEPARATOR).append(' ');
			}
			stringBuilder.append(string);
		}
		return stringBuilder.toString();
	}

	public static boolean contains(final List<String> requested, final List<String> claimed) {

		boolean found = false;
		for (final String element : requested) {

			if (!claimed.contains(element)) {
				found = false;
				break;
			}
			found = true;
		}
		return found;
	}

	public static long convertDuration(eu.europa.esig.jaxb.policy.TimeUnit fromJaxb, eu.europa.esig.jaxb.policy.TimeUnit toJaxb, int value) {
		TimeUnit from = TimeUnit.valueOf(fromJaxb.name());
		TimeUnit to = TimeUnit.valueOf(toJaxb.name());
		Long convert = to.convert(value, from);
		if (convert == 0) {
			return Long.MAX_VALUE;
		} else {
			return convert.longValue();
		}
	}

	public static long convertDuration(TimeConstraint timeConstraint) {
		if (timeConstraint != null) {
			return convertDuration(timeConstraint.getUnit(), eu.europa.esig.jaxb.policy.TimeUnit.MILLISECONDS, timeConstraint.getValue());
		}
		return Long.MAX_VALUE;
	}

}
