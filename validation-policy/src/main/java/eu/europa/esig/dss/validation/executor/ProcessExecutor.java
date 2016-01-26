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

import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.reports.Reports;

/**
 * This interface allows to define how the validation process should be carried out.
 */
public interface ProcessExecutor {

	/**
	 * This method allows to set the {@code Date} that is used
	 * during the validation process execution.
	 *
	 * @param diagnosticData
	 */
	void getCurrentTime(Date currentDate);

	/**
	 * This method allows to set the
	 * {@code eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData} that is used
	 * during the validation process execution.
	 *
	 * @param diagnosticData
	 */
	void setDiagnosticData(DiagnosticData diagnosticData);

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
	 * This method allows to set the validation level that is used during the
	 * validation process execution.
	 *
	 * @param validationLevel
	 *            the validation level.
	 */
	void setValidationLevel(ValidationLevel validationLevel);

	/**
	 * This method allows to run the validation process.
	 *
	 * @return {@code Reports}
	 */
	Reports execute();

	Date getCurrentTime();

}
