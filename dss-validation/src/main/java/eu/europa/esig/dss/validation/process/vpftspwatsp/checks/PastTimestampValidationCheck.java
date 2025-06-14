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
package eu.europa.esig.dss.validation.process.vpftspwatsp.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.AbstractPastTokenValidationCheck;

/**
 * Checks if timestamp's past validation is acceptable
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class PastTimestampValidationCheck<T extends XmlConstraintsConclusion> extends AbstractPastTokenValidationCheck<T> {

	/** The validated timestamp */
	private TimestampWrapper timestamp;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlConstraintsConclusion}
	 * @param timestamp {@link TimestampWrapper}
	 * @param xmlPSV {@link XmlPSV}
	 * @param constraint {@link LevelRule}
	 */
	public PastTimestampValidationCheck(I18nProvider i18nProvider, T result, TimestampWrapper timestamp, XmlPSV xmlPSV,
										LevelRule constraint) {
		super(i18nProvider, result, timestamp, xmlPSV, constraint);
		this.timestamp = timestamp;
	}

	@Override
	protected XmlBlockType getBlockType() {
		return XmlBlockType.TST_PSV;
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

}
