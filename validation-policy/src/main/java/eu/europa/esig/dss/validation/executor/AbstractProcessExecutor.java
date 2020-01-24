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
package eu.europa.esig.dss.validation.executor;

import java.util.Date;
import java.util.Locale;
import java.util.Objects;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.ValidationPolicy;

public class AbstractProcessExecutor {

	protected Date currentTime = new Date();
	protected ValidationPolicy policy;
	protected XmlDiagnosticData jaxbDiagnosticData;
	
	private I18nProvider i18nProvider;

	public void setCurrentTime(Date currentTime) {
		this.currentTime = currentTime;
	}

	public Date getCurrentTime() {
		return currentTime;
	}

	public void setDiagnosticData(XmlDiagnosticData diagnosticData) {
		this.jaxbDiagnosticData = diagnosticData;
	}

	public void setValidationPolicy(ValidationPolicy validationPolicy) {
		this.policy = validationPolicy;
	}

	public ValidationPolicy getValidationPolicy() {
		return policy;
	}

	public void setLocale(Locale locale) {
		Objects.requireNonNull(locale, "Locale cannot be null!");
		i18nProvider = new I18nProvider(locale);
	}
	
	protected I18nProvider getI18nProvider() {
		if (i18nProvider == null) {
			i18nProvider = new I18nProvider(Locale.getDefault());
		}
		return i18nProvider;
	}
	
	protected void assertConfigurationValid() {
		Objects.requireNonNull(jaxbDiagnosticData, "The diagnostic data is missing");
		Objects.requireNonNull(policy, "The validation policy is missing");
		Objects.requireNonNull(currentTime, "The current time is missing");
	}

}
