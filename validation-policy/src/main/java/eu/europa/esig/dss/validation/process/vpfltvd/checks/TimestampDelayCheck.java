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

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.validation.policy.RuleUtils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.TimeConstraint;

public class TimestampDelayCheck extends ChainItem<XmlValidationProcessLongTermData> {

	private final SignatureWrapper signature;
	private final Date bestSignatureTime;
	private final TimeConstraint timeConstraint;

	public TimestampDelayCheck(XmlValidationProcessLongTermData result, SignatureWrapper signature, Date bestSignatureTime, TimeConstraint timeConstraint) {
		super(result, timeConstraint);

		this.signature = signature;
		this.bestSignatureTime = bestSignatureTime;

		this.timeConstraint = timeConstraint;
	}

	@Override
	protected boolean process() {
		Date signingTime = signature.getDateTime();
		if (signingTime == null) {
			return false;
		}
		long delayMilliseconds = RuleUtils.convertDuration(timeConstraint);
		Date limit;
		if (delayMilliseconds == Long.MAX_VALUE) {
			limit = new Date(Long.MAX_VALUE);
		} else {
			limit = new Date((signingTime.getTime() + delayMilliseconds));
		}
		return limit.after(bestSignatureTime);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ADEST_ISTPTDABST;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ADEST_ISTPTDABST_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIG_CONSTRAINTS_FAILURE;
	}

}
