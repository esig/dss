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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

/**
 * Checks if timestamp's past validation is acceptable
 */
public class PastTimestampValidation extends ChainItem<XmlValidationProcessArchivalData> {

	/** The validated timestamp */
	private TimestampWrapper timestamp;

	/** Past signature validation */
	private XmlPSV xmlPSV;

	/** Current Indication */
	private Indication indication;

	/** Current SubIndication */
	private SubIndication subIndication;

	/** Past signature validation suffic */
	private static final String PSV_BLOCK_SUFFIX = "-PSV";

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlValidationProcessArchivalData}
	 * @param xmlPSV {@link XmlPSV}
	 * @param timestamp {@link TimestampWrapper}
	 * @param constraint {@link LevelConstraint}
	 */
	public PastTimestampValidation(I18nProvider i18nProvider, XmlValidationProcessArchivalData result, XmlPSV xmlPSV,
								   TimestampWrapper timestamp, LevelConstraint constraint) {
		super(i18nProvider, result, constraint, timestamp.getId() + PSV_BLOCK_SUFFIX);
		this.timestamp = timestamp;
		this.xmlPSV = xmlPSV;
	}

	@Override
	protected XmlBlockType getBlockType() {
		return XmlBlockType.TST_PSV;
	}

	@Override
	protected boolean process() {
		if (!isValid(xmlPSV)) {
			indication = xmlPSV.getConclusion().getIndication();
			subIndication = xmlPSV.getConclusion().getSubIndication();
			return false;
		}
		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.PSV_IPTVC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.PSV_IPTVC_ANS;
	}

	@Override
	protected String buildAdditionalInfo() {
		String date = ValidationProcessUtils.getFormattedDate(timestamp.getProductionTime());
		return i18nProvider.getMessage(MessageTag.TIMESTAMP_VALIDATION,
				ValidationProcessUtils.getTimestampTypeMessageTag(timestamp.getType()), timestamp.getId(), date);
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return indication;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return subIndication;
	}

}
