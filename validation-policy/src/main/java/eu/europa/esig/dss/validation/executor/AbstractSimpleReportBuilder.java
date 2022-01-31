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

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlValidationPolicy;

import java.util.Date;

/**
 * Abstract code for SimpleReport builder
 */
public abstract class AbstractSimpleReportBuilder {

	/** The validation time */
	private final Date currentTime;

	/** The validation policy */
	private final ValidationPolicy policy;

	/** The DiagnosticData to use */
	protected final DiagnosticData diagnosticData;

	/** The detailed report */
	protected final DetailedReport detailedReport;

	/**
	 * Default constructor
	 *
	 * @param currentTime {@link Date} validation time
	 * @param policy {@link ValidationPolicy}
	 * @param diagnosticData {@link DiagnosticData}
	 * @param detailedReport {@link DetailedReport}
	 */
	protected AbstractSimpleReportBuilder(Date currentTime, ValidationPolicy policy, DiagnosticData diagnosticData,
									   DetailedReport detailedReport) {
		this.currentTime = currentTime;
		this.policy = policy;
		this.diagnosticData = diagnosticData;
		this.detailedReport = detailedReport;
	}

	/**
	 * This method generates the validation simpleReport.
	 *
	 * @return the object representing {@code XmlSimpleReport}
	 */
	public XmlSimpleReport build() {

		XmlSimpleReport simpleReport = new XmlSimpleReport();

		addPolicyNode(simpleReport);
		addValidationTime(simpleReport);
		addDocumentName(simpleReport);

		boolean containerInfoPresent = diagnosticData.isContainerInfoPresent();
		if (containerInfoPresent) {
			addContainerType(simpleReport);
		}

		return simpleReport;
	}

	private void addPolicyNode(XmlSimpleReport report) {
		XmlValidationPolicy xmlPolicy = new XmlValidationPolicy();
		xmlPolicy.setPolicyName(policy.getPolicyName());
		xmlPolicy.setPolicyDescription(policy.getPolicyDescription());
		report.setValidationPolicy(xmlPolicy);
	}

	private void addValidationTime(XmlSimpleReport report) {
		report.setValidationTime(currentTime);
	}

	private void addDocumentName(XmlSimpleReport report) {
		report.setDocumentName(diagnosticData.getDocumentName());
	}

	private void addContainerType(XmlSimpleReport simpleReport) {
		simpleReport.setContainerType(diagnosticData.getContainerType());
	}

}
