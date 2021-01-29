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
package eu.europa.esig.dss.validation.process.vpfbs.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractBasicBuildingBlocksCheck;

import java.util.List;
import java.util.Map;

/**
 * Validates signature's basic building blocks
 */
public class SignatureBasicBuildingBlocksCheck extends AbstractBasicBuildingBlocksCheck<XmlValidationProcessBasicSignature> {

	private final XmlBasicBuildingBlocks signatureBBB;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlValidationProcessBasicSignature}
	 * @param diagnosticData {@link DiagnosticData}
	 * @param signatureBBB {@link XmlBasicBuildingBlocks}
	 * @param bbbs map of all BBBs
	 * @param constraint {@link LevelConstraint}
	 */
	public SignatureBasicBuildingBlocksCheck(I18nProvider i18nProvider, XmlValidationProcessBasicSignature result,
											 DiagnosticData diagnosticData, XmlBasicBuildingBlocks signatureBBB,
											 Map<String, XmlBasicBuildingBlocks> bbbs, LevelConstraint constraint) {
		super(i18nProvider, result, diagnosticData, signatureBBB, bbbs, constraint);
		this.signatureBBB = signatureBBB;

		result.setProofOfExistence(getCurrentTime(diagnosticData));
	}

	@Override
	protected XmlBlockType getBlockType() {
		return XmlBlockType.SIG_BBB;
	}

	private XmlProofOfExistence getCurrentTime(DiagnosticData diagnosticData) {
		XmlProofOfExistence proofOfExistence = new XmlProofOfExistence();
		proofOfExistence.setTime(diagnosticData.getValidationDate());
		return proofOfExistence;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ADEST_ROBVPIIC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ADEST_ROBVPIIC_ANS;
	}

	@Override
	protected List<XmlMessage> getPreviousErrors() {
		return signatureBBB.getConclusion().getErrors();
	}

}
