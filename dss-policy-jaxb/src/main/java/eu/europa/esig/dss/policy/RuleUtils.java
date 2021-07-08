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
package eu.europa.esig.dss.policy;

import eu.europa.esig.dss.policy.jaxb.TimeConstraint;

import java.util.concurrent.TimeUnit;

/**
 * Converts {@code TimeConstraint} from a policy into the corresponding long time value
 */
public final class RuleUtils {

	private RuleUtils() {
	}

	/**
	 * Converts the given {@code value} to the corresponding long value
	 *
	 * @param fromJaxb {@code eu.europa.esig.dss.policy.jaxb.TimeUnit} of the value
	 * @param toJaxb {@code eu.europa.esig.dss.policy.jaxb.TimeUnit} to obtain
	 * @param value integer value to convert
	 * @return long time value
	 */
	public static long convertDuration(eu.europa.esig.dss.policy.jaxb.TimeUnit fromJaxb,
									   eu.europa.esig.dss.policy.jaxb.TimeUnit toJaxb, int value) {
		TimeUnit from = TimeUnit.valueOf(fromJaxb.name());
		TimeUnit to = TimeUnit.valueOf(toJaxb.name());
		Long convert = to.convert(value, from);
		return convert;
	}

	/**
	 * Converts the {@code TimeConstraint} to the corresponding long time value in milliseconds
	 *
	 * @param timeConstraint {@link TimeConstraint}
	 * @return long time value in milliseconds
	 */
	public static long convertDuration(TimeConstraint timeConstraint) {
		if (timeConstraint != null) {
			return convertDuration(timeConstraint.getUnit(),
					eu.europa.esig.dss.policy.jaxb.TimeUnit.MILLISECONDS, timeConstraint.getValue());
		}
		return Long.MAX_VALUE;
	}

}
