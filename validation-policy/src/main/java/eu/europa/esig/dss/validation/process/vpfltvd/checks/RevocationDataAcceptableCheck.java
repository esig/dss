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
package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRevocationBasicValidation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

/**
 * Verifies the result of a basic revocation validation process
 *
 */
public class RevocationDataAcceptableCheck extends ChainItem<XmlValidationProcessLongTermData> {

	/**
	 * The revocation basic validation result
	 */
	private final XmlRevocationBasicValidation revocationBasicValidation;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlValidationProcessLongTermData}
	 * @param revocationBasicValidation {@link XmlRevocationBasicValidation}
	 * @param constraint {@link LevelConstraint}
	 */
	public RevocationDataAcceptableCheck(I18nProvider i18nProvider, XmlValidationProcessLongTermData result,
										 XmlRevocationBasicValidation revocationBasicValidation, LevelConstraint constraint) {
		super(i18nProvider, result, constraint, revocationBasicValidation.getId());
		this.revocationBasicValidation = revocationBasicValidation;
	}

	@Override
	protected XmlBlockType getBlockType() {
		return XmlBlockType.REV_BBB;
	}

	@Override
	protected boolean process() {
		return revocationBasicValidation.getConclusion() != null &&
				ValidationProcessUtils.isAllowedBasicSignatureValidation(revocationBasicValidation.getConclusion());
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return revocationBasicValidation.getConclusion().getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return revocationBasicValidation.getConclusion().getSubIndication();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ADEST_RORPIIC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ADEST_RORPIIC_ANS;
	}

}
