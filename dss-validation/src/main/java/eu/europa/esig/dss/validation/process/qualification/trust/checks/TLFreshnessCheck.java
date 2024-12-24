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
package eu.europa.esig.dss.validation.process.qualification.trust.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.RuleUtils;
import eu.europa.esig.dss.policy.jaxb.TimeConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.Date;

/**
 * Verifies whether the Trusted List is fresh
 *
 */
public class TLFreshnessCheck extends ChainItem<XmlTLAnalysis> {

	/** Trusted List to check */
	private final XmlTrustedList currentTL;

	/** Validation time */
	private final Date currentTime;

	/** Constraint defining the maximum freshness time */
	private final TimeConstraint timeConstraint;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlTLAnalysis}
	 * @param currentTL {@link XmlTrustedList}
	 * @param currentTime {@link Date}
	 * @param timeConstraint {@link TimeConstraint}
	 */
	public TLFreshnessCheck(I18nProvider i18nProvider, XmlTLAnalysis result, XmlTrustedList currentTL,
							Date currentTime, TimeConstraint timeConstraint) {
		super(i18nProvider, result, timeConstraint);
		this.currentTL = currentTL;
		this.currentTime = currentTime;
		this.timeConstraint = timeConstraint;
	}

	@Override
	protected boolean process() {
		long maxFreshness = getMaxFreshness();
		long validationDateTime = currentTime.getTime();
		long limit = validationDateTime - maxFreshness;

		Date lastLoading = currentTL.getLastLoading();
		return lastLoading != null && lastLoading.after(new Date(limit));
	}

	private long getMaxFreshness() {
		return RuleUtils.convertDuration(timeConstraint);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_TL_FRESH;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_TL_FRESH_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}

}
