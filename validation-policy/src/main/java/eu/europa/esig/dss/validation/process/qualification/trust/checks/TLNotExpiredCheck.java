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
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;

public class TLNotExpiredCheck extends ChainItem<XmlTLAnalysis> {

	private final XmlTrustedList currentTL;
	private final Date currentTime;

	public TLNotExpiredCheck(I18nProvider i18nProvider, XmlTLAnalysis result, XmlTrustedList currentTL, Date currentTime, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.currentTL = currentTL;
		this.currentTime = currentTime;
	}

	@Override
	protected boolean process() {
		Date nextUpdate = currentTL.getNextUpdate();
		return (nextUpdate != null) && (nextUpdate.after(currentTime));
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_TL_EXP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_TL_EXP_ANS;
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
