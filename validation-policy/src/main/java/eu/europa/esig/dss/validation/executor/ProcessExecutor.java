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

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.reports.AbstractReports;

/**
 * This interface allows to define how the validation process should be carried out.
 */
public interface ProcessExecutor<R extends AbstractReports> {

	/**
	 * This method allows to set the {@code Date} that is used
	 * during the validation process execution.
	 *
	 * @param currentDate
	 *            the current time
	 */
	void setCurrentTime(Date currentDate);

	/**
	 * This method allows to set the {@code XmlDiagnosticData} that is used during
	 * the validation process execution.
	 *
	 * @param diagnosticData
	 *                       the JAXB diagnostic data
	 */
	void setDiagnosticData(XmlDiagnosticData diagnosticData);

	/**
	 * This method allows to set the validation policy that is used during the
	 * validation process execution.
	 *
	 * @param validationPolicy
	 *            the representation of the validation policy.
	 */
	void setValidationPolicy(ValidationPolicy validationPolicy);

	ValidationPolicy getValidationPolicy();

	/**
	 * Returns the validation time {@code Date}
	 * 
	 * @return {@link Date}
	 */
	Date getCurrentTime();
	
	/**
	 * Allows to set a language setting for generated Reports
	 * 
	 * @param locale {@link Locale}
	 */
	void setLocale(Locale locale);

	/**
	 * This method allows to run the validation process.
	 *
	 * @return the {@code Reports}
	 */
	R execute();

}
