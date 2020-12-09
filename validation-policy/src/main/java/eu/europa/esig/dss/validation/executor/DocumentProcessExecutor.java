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

import eu.europa.esig.dss.validation.reports.Reports;

/**
 * Processes a document validation
 */
public interface DocumentProcessExecutor extends ProcessExecutor<Reports> {

	/**
	 * This method allows to set the validation level that is used during the
	 * validation process execution.
	 *
	 * @param validationLevel
	 *            the validation level.
	 */
	void setValidationLevel(ValidationLevel validationLevel);
	
	/**
	 * Specifies if the ETSI Validation Report must be created
	 * 
	 * @param enableEtsiValidationReport enable the ETSI Validation Report
	 *                                   generation
	 */
	void setEnableEtsiValidationReport(boolean enableEtsiValidationReport);

	/**
	 * This method allows to enable/disable the semantics inclusion in the reports
	 * (Indication / SubIndication meanings)
	 * 
	 * Disabled by default
	 * 
	 * @param includeSemantics true to enable the inclusion of the semantics
	 */
	void setIncludeSemantics(boolean includeSemantics);

}
