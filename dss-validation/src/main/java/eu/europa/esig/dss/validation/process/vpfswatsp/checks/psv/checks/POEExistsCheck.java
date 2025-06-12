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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;

import java.util.Date;

/**
 * Checks if the POE exists
 */
public class POEExistsCheck extends ChainItem<XmlPSV> {

	/** Token to be validated */
	private final TokenProxy token;

	/** Time when the signature validity can be proved */
	private final Date controlTime;

	/** Set of available POEs */
	private final POEExtraction poe;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlPSV}
	 * @param token {@link TokenProxy}
	 * @param controlTime {@link java.util.Date}
	 * @param poe {@link POEExtraction}
	 * @param constraint {@link LevelRule}
	 */
	public POEExistsCheck(I18nProvider i18nProvider, XmlPSV result, TokenProxy token, Date controlTime,
						  POEExtraction poe, LevelRule constraint) {
		super(i18nProvider, result, constraint);
		this.token = token;
		this.controlTime = controlTime;
		this.poe = poe;
	}

	@Override
	protected XmlBlockType getBlockType() {
		return XmlBlockType.PCV;
	}

	@Override
	public boolean process() {
		return controlTime != null && poe.isPOEExists(token.getId(), controlTime);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.PSV_ITPOSVAOBCT;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.PSV_ITPOSVAOBCT_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return null;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}

	@Override
	protected String buildAdditionalInfo() {
		return i18nProvider.getMessage(MessageTag.CONTROL_TIME_WITH_POE, ValidationProcessUtils.getFormattedDate(controlTime),
				ValidationProcessUtils.getFormattedDate(poe.getLowestPOETime(token.getId())));
	}

}
