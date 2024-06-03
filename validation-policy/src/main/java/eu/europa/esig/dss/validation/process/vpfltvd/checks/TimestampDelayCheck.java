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

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.RuleUtils;
import eu.europa.esig.dss.policy.jaxb.TimeConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.Date;

/**
 * Checks if the claimed signing time + timestamp's delay is after the best-signature-time
 */
public class TimestampDelayCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** Signature to check */
	private final SignatureWrapper signature;

	/** Best signature time */
	private final Date bestSignatureTime;

	/** Timestamp's delay constraint */
	private final TimeConstraint timeConstraint;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlConstraintsConclusion}
	 * @param signature {@link SignatureWrapper}
	 * @param bestSignatureTime {@link Date}
	 * @param timeConstraint {@link TimeConstraint}
	 */
	public TimestampDelayCheck(I18nProvider i18nProvider, T result,
							   SignatureWrapper signature, Date bestSignatureTime, TimeConstraint timeConstraint) {
		super(i18nProvider, result, timeConstraint);

		this.signature = signature;
		this.bestSignatureTime = bestSignatureTime;

		this.timeConstraint = timeConstraint;
	}

	@Override
	protected boolean process() {
		Date signingTime = signature.getClaimedSigningTime();
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
