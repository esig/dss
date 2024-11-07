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
package eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.List;

/**
 * Verifies if the RAC result is valid
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class RevocationAcceptanceCheckerResultCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** Revocation Acceptance Checker result */
	private final XmlRAC racResult;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param racResult {@link XmlRAC}
	 * @param constraint {@link LevelConstraint}
	 */
	public RevocationAcceptanceCheckerResultCheck(I18nProvider i18nProvider, T result, XmlRAC racResult, LevelConstraint constraint) {
		super(i18nProvider, result, constraint, racResult.getId());
		this.racResult = racResult;
	}

	@Override
	protected XmlBlockType getBlockType() {
		return XmlBlockType.RAC;
	}

	@Override
	protected boolean process() {
		return isValid(racResult);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_RAC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_RAC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return racResult.getConclusion().getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return racResult.getConclusion().getSubIndication();
	}
	
	@Override
	protected String buildAdditionalInfo() {
		if (racResult.getRevocationProductionDate() != null) {
			String thisUpdate = ValidationProcessUtils.getFormattedDate(racResult.getRevocationThisUpdate());
			String productionDate = ValidationProcessUtils.getFormattedDate(racResult.getRevocationProductionDate());
			return i18nProvider.getMessage(MessageTag.REVOCATION_ACCEPTANCE_CHECK, racResult.getId(), thisUpdate, productionDate);
		}
		return null;
	}

	@Override
	public List<XmlMessage> getPreviousErrors() {
		return racResult.getConclusion().getErrors();
	}

}
