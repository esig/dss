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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlTLAnalysis;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedList;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.bbb.BasicBuildingBlocks;
import eu.europa.esig.dss.validation.process.qualification.trust.TLValidationBlock;
import eu.europa.esig.dss.validation.reports.wrapper.AbstractTokenProxy;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public abstract class AbstractDetailedReportBuilder {

	protected final DiagnosticData diagnosticData;
	protected final ValidationPolicy policy;
	protected final Date currentTime;

	protected AbstractDetailedReportBuilder(DiagnosticData diagnosticData, ValidationPolicy policy, Date currentTime) {
		this.diagnosticData = diagnosticData;
		this.policy = policy;
		this.currentTime = currentTime;

	}

	protected DetailedReport init() {
		DetailedReport detailedReport = new DetailedReport();

		if (policy.isEIDASConstraintPresent()) {
			detailedReport.getTLAnalysis().addAll(executeAllTlAnalysis(diagnosticData, policy, currentTime));
		}

		return detailedReport;
	}

	protected List<XmlTLAnalysis> executeAllTlAnalysis(DiagnosticData diagnosticData, ValidationPolicy policy, Date currentTime) {
		List<XmlTLAnalysis> result = new ArrayList<XmlTLAnalysis>();
		XmlTrustedList listOfTrustedLists = diagnosticData.getListOfTrustedLists();
		if (listOfTrustedLists != null) {
			TLValidationBlock tlValidation = new TLValidationBlock(listOfTrustedLists, currentTime, policy);
			result.add(tlValidation.execute());
		}

		// Validate used trusted lists
		List<XmlTrustedList> trustedLists = diagnosticData.getTrustedLists();
		if (Utils.isCollectionNotEmpty(trustedLists)) {
			for (XmlTrustedList xmlTrustedList : trustedLists) {
				TLValidationBlock tlValidation = new TLValidationBlock(xmlTrustedList, currentTime, policy);
				result.add(tlValidation.execute());
			}
		}
		return result;
	}

	protected void process(Set<? extends AbstractTokenProxy> tokensToProcess, Context context, Map<String, XmlBasicBuildingBlocks> bbbs) {
		for (AbstractTokenProxy token : tokensToProcess) {
			BasicBuildingBlocks bbb = new BasicBuildingBlocks(diagnosticData, token, currentTime, policy, context);
			XmlBasicBuildingBlocks result = bbb.execute();
			bbbs.put(token.getId(), result);
		}
	}

}
