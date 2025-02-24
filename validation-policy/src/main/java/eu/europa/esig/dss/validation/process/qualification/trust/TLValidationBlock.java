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
package eu.europa.esig.dss.validation.process.qualification.trust;

import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.TimeConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.trust.checks.TLFreshnessCheck;
import eu.europa.esig.dss.validation.process.qualification.trust.checks.TLMRACheck;
import eu.europa.esig.dss.validation.process.qualification.trust.checks.TLNotExpiredCheck;
import eu.europa.esig.dss.validation.process.qualification.trust.checks.TLVersionCheck;
import eu.europa.esig.dss.validation.process.qualification.trust.checks.TLWellSignedCheck;

import java.util.Date;

/**
 * This class is used to perform validation of a Trusted List
 *
 */
public class TLValidationBlock extends Chain<XmlTLAnalysis> {

	/** Trusted list to be validated */
	private final XmlTrustedList currentTL;

	/** Validation time */
	private final Date currentTime;

	/** The signature validation policy */
	private final ValidationPolicy policy;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param currentTL {@link XmlTrustedList}
	 * @param currentTime {@link Date}
	 * @param policy {@link ValidationPolicy}
	 */
	public TLValidationBlock(I18nProvider i18nProvider, XmlTrustedList currentTL, Date currentTime,
							 ValidationPolicy policy) {
		super(i18nProvider, new XmlTLAnalysis());

		result.setCountryCode(currentTL.getCountryCode());
		result.setURL(currentTL.getUrl());
		result.setId(currentTL.getId());

		this.currentTL = currentTL;
		this.currentTime = currentTime;
		this.policy = policy;
	}

	@Override
	protected String buildChainTitle() {
		if (Utils.isTrue(currentTL.isLOTL())) {
			return i18nProvider.getMessage(MessageTag.LOTL, currentTL.getCountryCode());
		} else {
			return i18nProvider.getMessage(MessageTag.TL, currentTL.getCountryCode());
		}
	}

	@Override
	protected void initChain() {

		ChainItem<XmlTLAnalysis> item = firstItem = tlFreshness();

		if (!isLastTL()) {
			item = item.setNextItem(tlNotExpired());
		}

		item = item.setNextItem(tlVersion());

		item = item.setNextItem(tlWellSigned());

		if (currentTL.isMra() != null && currentTL.isMra()) {
			item = item.setNextItem(tlMRAEnacted());
		}

	}

	private boolean isLastTL() {
		return currentTL.getNextUpdate() == null;
	}

	private ChainItem<XmlTLAnalysis> tlFreshness() {
		TimeConstraint constraint = policy.getTLFreshnessConstraint();
		return new TLFreshnessCheck(i18nProvider, result, currentTL, currentTime, constraint);
	}

	private ChainItem<XmlTLAnalysis> tlNotExpired() {
		LevelConstraint constraint = policy.getTLNotExpiredConstraint();
		return new TLNotExpiredCheck(i18nProvider, result, currentTL, currentTime, constraint);
	}

	private ChainItem<XmlTLAnalysis> tlVersion() {
		MultiValuesConstraint constraint = policy.getTLVersionConstraint();
		return new TLVersionCheck(i18nProvider, result, currentTL, currentTime, constraint);
	}

	private ChainItem<XmlTLAnalysis> tlWellSigned() {
		LevelConstraint constraint = policy.getTLWellSignedConstraint();
		return new TLWellSignedCheck(i18nProvider, result, currentTL, constraint);
	}

	private ChainItem<XmlTLAnalysis> tlMRAEnacted() {
		return new TLMRACheck(i18nProvider, result, currentTL, getInfoLevelConstraint());
	}

}
