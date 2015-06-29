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

import java.util.Date;

import org.w3c.dom.Document;

import eu.europa.esig.dss.validation.report.Reports;

/**
 * This interface allows to define how the validation process should be carried out.
 */
public interface ProcessExecutor {

	/**
	 * This method returns the {@code Date} against which the validation process is carried out.
	 *
	 * @return
	 */
	Date getCurrentTime();

	/**
	 * This method allows to set the {@code eu.europa.esig.dss.validation.report.DiagnosticData} that is used during the validation process execution.
	 *
	 * @param diagnosticDataDom
	 */
	void setDiagnosticDataDom(final Document diagnosticDataDom);

	/**
	 * This method allows to set the validation policy that is used during the validation process execution.
	 *
	 * @param validationPolicy DOM {@code Document} representation of the validation policy.
	 */
	void setValidationPolicy(final ValidationPolicy validationPolicy);

	/**
	 * @return {@code ValidationPolicy} which is used to validate the signatures
	 */
	ValidationPolicy  getValidationPolicy();

	/**
	 * This method allows to set the validation policy that is used during the validation process execution to validate the countersignatures.
	 *
	 * @param validationPolicy DOM {@code Document} representation of the validation policy.
	 */
	void setCountersignatureValidationPolicy(ValidationPolicy validationPolicy);

	/**
	 * This method allows to run the validation process.
	 *
	 * @return {@code Reports}
	 */
	Reports execute();
}
