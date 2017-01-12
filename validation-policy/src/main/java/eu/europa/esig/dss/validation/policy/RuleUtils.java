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

import java.util.concurrent.TimeUnit;

import eu.europa.esig.jaxb.policy.TimeConstraint;

public final class RuleUtils {

	private RuleUtils() {
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
