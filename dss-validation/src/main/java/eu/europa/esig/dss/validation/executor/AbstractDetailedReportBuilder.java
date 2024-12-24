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

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.diagnostic.AbstractTokenProxy;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.BasicBuildingBlocks;
import eu.europa.esig.dss.validation.process.qualification.trust.TLValidationBlock;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Abstract code for DetailedReport builder
 */
public abstract class AbstractDetailedReportBuilder {

	/** The i18n provider */
	protected final I18nProvider i18nProvider;

	/** The DiagnosticData to use */
	protected final DiagnosticData diagnosticData;

	/** The validation policy */
	protected final ValidationPolicy policy;

	/** The validation time */
	protected final Date currentTime;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param currentTime {@link Date} validation time
	 * @param policy {@link ValidationPolicy} to use
	 * @param diagnosticData {@link DiagnosticData}
	 */
	protected AbstractDetailedReportBuilder(I18nProvider i18nProvider, Date currentTime, ValidationPolicy policy,
											DiagnosticData diagnosticData) {
		this.i18nProvider = i18nProvider;
		this.currentTime = currentTime;
		this.policy = policy;
		this.diagnosticData = diagnosticData;
	}

	/**
	 * Initializes the {@code XmlDetailedReport} by adding the TL analysis
	 *
	 * @return {@link XmlDetailedReport}
	 */
	protected XmlDetailedReport init() {
		XmlDetailedReport detailedReport = new XmlDetailedReport();

		if (policy.isEIDASConstraintPresent()) {
			detailedReport.getTLAnalysis().addAll(executeAllTlAnalysis(diagnosticData, policy, currentTime));
		}

		return detailedReport;
	}

	/**
	 * Executes the TL analysis
	 *
	 * @param diagnosticData {@link DiagnosticData}
	 * @param policy {@link ValidationPolicy}
	 * @param currentTime {@link Date} validation time
	 * @return a list of {@link XmlTLAnalysis}
	 */
	protected List<XmlTLAnalysis> executeAllTlAnalysis(DiagnosticData diagnosticData, ValidationPolicy policy,
													   Date currentTime) {
		List<XmlTLAnalysis> result = new ArrayList<>();
		result.addAll(validateTL(policy, currentTime, diagnosticData.getListOfTrustedLists()));
		result.addAll(validateTL(policy, currentTime, diagnosticData.getTrustedLists()));
		return result;
	}

	private List<XmlTLAnalysis> validateTL(ValidationPolicy policy, Date currentTime, List<XmlTrustedList> trustedLists) {
		List<XmlTLAnalysis> result = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(trustedLists)) {
			for (XmlTrustedList xmlTrustedList : trustedLists) {
				TLValidationBlock tlValidation = new TLValidationBlock(i18nProvider, xmlTrustedList, currentTime, policy);
				result.add(tlValidation.execute());
			}
		}
		return result;
	}

	/**
	 * Process the tokens validation
	 *
	 * @param tokensToProcess collection of tokens to validate
	 * @param context {@link Context} validation context
	 * @param bbbs map of BasicBuildingBlocks
	 */
	protected void process(Collection<? extends AbstractTokenProxy> tokensToProcess, Context context,
						   Map<String, XmlBasicBuildingBlocks> bbbs) {
		for (AbstractTokenProxy token : tokensToProcess) {
			BasicBuildingBlocks bbb = new BasicBuildingBlocks(
					i18nProvider, diagnosticData, token, currentTime, bbbs, policy, context);
			XmlBasicBuildingBlocks result = bbb.execute();
			bbbs.put(token.getId(), result);
		}
	}

}
