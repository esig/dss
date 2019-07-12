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
package eu.europa.esig.dss.validation.process.qualification.trust.checks;

import java.util.Date;

import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedList;
import eu.europa.esig.dss.validation.policy.RuleUtils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.TimeConstraint;

public class TLFreshnessCheck extends ChainItem<XmlTLAnalysis> {

	private final XmlTrustedList currentTL;
	private final Date currentTime;
	private final TimeConstraint timeConstraint;

	public TLFreshnessCheck(XmlTLAnalysis result, XmlTrustedList currentTL, Date currentTime, TimeConstraint timeConstraint) {
		super(result, timeConstraint);
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
