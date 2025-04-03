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
package eu.europa.esig.dss.validation.executor;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.model.policy.ValidationPolicy;

import java.util.Date;
import java.util.Locale;
import java.util.Objects;

/**
 * Abstract validation process executor
 */
public abstract class AbstractProcessExecutor {

	/** Validation time */
	protected Date currentTime = new Date();

	/** Validation policy */
	protected ValidationPolicy policy;

	/** DiagnosticData */
	protected XmlDiagnosticData jaxbDiagnosticData;

	/** i18n provider */
	private I18nProvider i18nProvider;

	/**
	 * Default constructor instantiating object with null values and current time
	 */
	protected AbstractProcessExecutor() {
	}

	/**
	 * Sets the validation time
	 *
	 * @param currentTime {@link Date}
	 */
	public void setCurrentTime(Date currentTime) {
		this.currentTime = currentTime;
	}

	/**
	 * Gets the validation time
	 *
	 * @return {@link Date}
	 */
	public Date getCurrentTime() {
		return currentTime;
	}

	/**
	 * Sets the DiagnosticData
	 *
	 * @param diagnosticData {@link XmlDiagnosticData}
	 */
	public void setDiagnosticData(XmlDiagnosticData diagnosticData) {
		this.jaxbDiagnosticData = diagnosticData;
	}

	/**
	 * Gets the validation policy
	 *
	 * @return {@link ValidationPolicy}
	 */
	public ValidationPolicy getValidationPolicy() {
		return policy;
	}

	/**
	 * Sets the validation policy
	 *
	 * @param validationPolicy {@link ValidationPolicy}
	 */
	public void setValidationPolicy(ValidationPolicy validationPolicy) {
		this.policy = validationPolicy;
	}

	/**
	 * Sets the locale to use to generate messages
	 *
	 * @param locale {@link Locale}
	 */
	public void setLocale(Locale locale) {
		Objects.requireNonNull(locale, "Locale cannot be null!");
		i18nProvider = new I18nProvider(locale);
	}

	/**
	 * Gets the i18nProvider
	 *
	 * @return {@link I18nProvider}
	 */
	protected I18nProvider getI18nProvider() {
		if (i18nProvider == null) {
			i18nProvider = new I18nProvider(Locale.getDefault());
		}
		return i18nProvider;
	}

	/**
	 * Checks if the configuration valid
	 */
	protected void assertConfigurationValid() {
		Objects.requireNonNull(jaxbDiagnosticData, "The diagnostic data is missing");
		Objects.requireNonNull(policy, "The validation policy is missing");
		Objects.requireNonNull(currentTime, "The current time is missing");
	}

}
