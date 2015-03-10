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
package eu.europa.ec.markt.dss.validation102853;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.validation102853.policy.ProcessParameters;
import eu.europa.ec.markt.dss.validation102853.policy.ValidationPolicy;
import eu.europa.ec.markt.dss.validation102853.processes.LongTermValidation;
import eu.europa.ec.markt.dss.validation102853.report.DetailedReport;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReportBuilder;
import eu.europa.ec.markt.dss.validation102853.rules.NodeName;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;
import eu.europa.ec.markt.dss.validation102853.xml.XmlNode;

/**
 * This class allows to carry out the validation process with in a specific context.
 */
public class CustomProcessExecutor implements ProcessExecutor {

	protected static final Logger LOG = LoggerFactory.getLogger(CustomProcessExecutor.class);

	/**
	 * DOM representation of the diagnostic data.
	 */
	protected Document diagnosticDataDom;

	protected DiagnosticData diagnosticData;

	/**
	 * Wrapper for the validation policy constraints
	 */
	protected ValidationPolicy validationPolicy;

	/**
	 * Wrapper for the countersignature validation policy constraints
	 */
	protected ValidationPolicy countersignatureValidationPolicy;

	protected ProcessParameters processParams;

	/**
	 * The simple validation report, contains only the most important information like validation date, signer from DN,
	 * indication, sub-indication...
	 */
	protected SimpleReport simpleReport;

	/**
	 * The detailed report contains all information collected during the validation process.
	 */
	protected DetailedReport detailedReport;

	/**
	 * See {@link eu.europa.ec.markt.dss.validation102853.policy.ProcessParameters#getCurrentTime()}
	 */
	protected Date currentTime = new Date();

	/**
	 * This is the default constructor. The process parameters must be initialised wih setters: {@code setDiagnosticDataDom} and {@code setValidationPolicyDom}
	 */
	public CustomProcessExecutor() {

	}

	@Override
	public void setDiagnosticDataDom(final Document diagnosticDataDom) {
		this.diagnosticDataDom = diagnosticDataDom;
	}

	@Override
	public void setValidationPolicy(final ValidationPolicy validationPolicy) {
		this.validationPolicy = validationPolicy;
	}

	@Override
	public ValidationPolicy getValidationPolicy() {
		return validationPolicy;
	}

	@Override
	public void setCountersignatureValidationPolicy(ValidationPolicy validationPolicy) {
		this.countersignatureValidationPolicy = validationPolicy;
	}

	/**
	 * This method executes the long term validation processes. The underlying processes are automatically executed.
	 */
	@Override
	public Reports execute() {

		processParams = new ProcessParameters();
		diagnosticData = new DiagnosticData(diagnosticDataDom);
		processParams.setDiagnosticData(diagnosticData);
		processParams.setValidationPolicy(validationPolicy);
		processParams.setCountersignatureValidationPolicy(countersignatureValidationPolicy);
		processParams.setCurrentTime(currentTime);
		final XmlDom usedCertificates = diagnosticData.getElement("/DiagnosticData/UsedCertificates");
		processParams.setCertPool(usedCertificates);

		final XmlNode mainNode = new XmlNode(NodeName.VALIDATION_DATA);
		mainNode.setNameSpace(XmlDom.NAMESPACE);

		final LongTermValidation ltv = new LongTermValidation();
		ltv.run(mainNode, processParams);

		final Document validationReportDocument = mainNode.toDocument();
		detailedReport = new DetailedReport(validationReportDocument);

		final SimpleReportBuilder simpleReportBuilder = new SimpleReportBuilder(validationPolicy, diagnosticData);
		simpleReport = simpleReportBuilder.build(processParams);

		final Reports reports = new Reports(diagnosticData, detailedReport, simpleReport);
		return reports;
	}

	/**
	 * Returns the time of the validation.
	 *
	 * @return
	 */
	@Override
	public Date getCurrentTime() {
		return currentTime;
	}
}
