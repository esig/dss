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
package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

/**
 * Verifies the result of a basic revocation validation process
 *
 * @param <T> implementation of the block's conclusion
 */
public class RevocationDataAcceptableCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/**
	 * The Id of a revocation data to be checked
	 */
	private final String revocationId;

	/**
	 * The revocation basic validation result
	 */
	private final XmlConclusion xmlConclusion;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlConstraintsConclusion}
	 * @param revocationId {@link String}
	 * @param xmlConclusion {@link XmlConclusion}
	 * @param constraint {@link LevelRule}
	 */
	public RevocationDataAcceptableCheck(I18nProvider i18nProvider, T result,
										 String revocationId, XmlConclusion xmlConclusion, LevelRule constraint) {
		super(i18nProvider, result, constraint, revocationId);
		this.revocationId = revocationId;
		this.xmlConclusion = xmlConclusion;
	}

	@Override
	protected XmlBlockType getBlockType() {
		return XmlBlockType.REV_BBB;
	}

	@Override
	protected boolean process() {
		return ValidationProcessUtils.isAllowedBasicRevocationDataValidation(xmlConclusion);
	}

	@Override
	protected String buildAdditionalInfo() {
		return i18nProvider.getMessage(MessageTag.TOKEN_ID, revocationId);
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return xmlConclusion.getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return xmlConclusion.getSubIndication();
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
