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
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.List;

/**
 * Abstract class to check if the given value is one of the allowed values by ValidationPolicy
 * @param <T> {@code XmlConstraintsConclusion}
 *
 */
public abstract class AbstractMultiValuesCheckItem<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** The constraint value */
	private final MultiValuesConstraint constraint;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param constraint {@link MultiValuesConstraint}
	 */
	protected AbstractMultiValuesCheckItem(I18nProvider i18nProvider, T result, MultiValuesConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.constraint = constraint;
	}

	/**
	 * Checks the value
	 *
	 * @param value {@link String} to check
	 * @return TRUE if the value is allowed by the constraint, FALSE otherwise
	 */
	protected boolean processValueCheck(String value) {
		return ValidationProcessUtils.processValueCheck(value, constraint.getId());
	}

	/**
	 * Checks the values
	 *
	 * @param values {@link String} to check
	 * @return TRUE if the values are allowed by the constraint, FALSE otherwise
	 */
	protected boolean processValuesCheck(List<String> values) {
		return ValidationProcessUtils.processValuesCheck(values, constraint.getId());
	}

}
