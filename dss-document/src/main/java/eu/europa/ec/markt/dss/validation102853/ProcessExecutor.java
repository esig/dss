/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */
package eu.europa.ec.markt.dss.validation102853;

import java.util.Date;

import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.validation102853.policy.ValidationPolicy;
import eu.europa.ec.markt.dss.validation102853.report.Reports;

/**
 * This interface allows to define how the validation process should be carried out.
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public interface ProcessExecutor {

	/**
	 * This method returns the {@code Date} against which the validation process is carried out.
	 *
	 * @return
	 */
	Date getCurrentTime();

	/**
	 * This method allows to set the {@code eu.europa.ec.markt.dss.validation102853.report.DiagnosticData} that is used during the validation process execution.
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
