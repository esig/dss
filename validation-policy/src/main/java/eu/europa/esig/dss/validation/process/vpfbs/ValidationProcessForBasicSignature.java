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
package eu.europa.esig.dss.validation.process.vpfbs;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.vpfbs.checks.SignatureBasicBuildingBlocksCheck;

import java.util.List;
import java.util.Map;

/**
 * 5.3 Validation process for Basic Signature
 */
public class ValidationProcessForBasicSignature extends Chain<XmlValidationProcessBasicSignature> {

	/** Diagnostic Data */
	private final DiagnosticData diagnosticData;

	/** The signature */
	private final SignatureWrapper signature;

	/** Map of BasicBuildingBlocks */
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param diagnosticData {@link DiagnosticData}
	 * @param signature {@link SignatureWrapper}
	 * @param bbbs map of BasicBuildingBlocks
	 */
	public ValidationProcessForBasicSignature(I18nProvider i18nProvider, DiagnosticData diagnosticData,
											  SignatureWrapper signature, Map<String, XmlBasicBuildingBlocks> bbbs) {
		super(i18nProvider, new XmlValidationProcessBasicSignature());
		this.diagnosticData = diagnosticData;
		this.signature = signature;
		this.bbbs = bbbs;
	}
	
	@Override
	protected MessageTag getTitle() {
		return MessageTag.VPBS;
	}

	@Override
	protected void initChain() {
		firstItem = basicBuildingBlocks();
	}

	private ChainItem<XmlValidationProcessBasicSignature> basicBuildingBlocks() {
		XmlBasicBuildingBlocks signatureBBB = bbbs.get(signature.getId());
		if (signatureBBB == null) {
			throw new IllegalStateException(String.format("Missing Basic Building Blocks result for token '%s'", signature.getId()));
		}
		return new SignatureBasicBuildingBlocksCheck(i18nProvider, result, diagnosticData, signatureBBB, bbbs, getFailLevelConstraint());
	}

	@Override
	protected void collectMessages(XmlConclusion conclusion, XmlConstraint constraint) {
		super.collectMessages(conclusion, constraint);

		XmlBasicBuildingBlocks signatureBBB = bbbs.get(signature.getId());
		List<XmlMessage> warnings = signatureBBB.getConclusion().getWarnings();
		if (Utils.isCollectionNotEmpty(warnings)) {
			conclusion.getWarnings().addAll(warnings);
		}
		List<XmlMessage> infos = signatureBBB.getConclusion().getInfos();
		if (Utils.isCollectionNotEmpty(infos)) {
			conclusion.getInfos().addAll(infos);
		}
	}

}
