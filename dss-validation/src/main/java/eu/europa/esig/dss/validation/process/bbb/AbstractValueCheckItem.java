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
package eu.europa.esig.dss.validation.process.bbb;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.jaxb.ValueConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks if the value is allowed
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public abstract class AbstractValueCheckItem<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** Accepts all values */
	private static final String ALL_VALUE = "*";

	/** Value constraint */
	private final ValueConstraint constraint;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param constraint {@link ValueConstraint}
	 */
	protected AbstractValueCheckItem(I18nProvider i18nProvider, T result, ValueConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.constraint = constraint;
	}

	/**
	 * Processes the value check
	 *
	 * @param value {@link String} to check
	 * @return TRUE if the {@code value} matches the {@code expected}, FALSE otherwise
	 */
	protected boolean processValueCheck(String value) {
		if (Utils.isStringEmpty(value)) {
			return false;
		}
		String expected = constraint.getValue();
		if (ALL_VALUE.equals(expected)) {
			return true;
		} else {
			return Utils.areStringsEqual(expected, value);
		}
	}

}
