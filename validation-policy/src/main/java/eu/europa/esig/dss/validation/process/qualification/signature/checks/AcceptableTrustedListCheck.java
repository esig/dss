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
package eu.europa.esig.dss.validation.process.qualification.signature.checks;

import java.text.MessageFormat;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlTLAnalysis;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class AcceptableTrustedListCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	private final XmlTLAnalysis tlAnalysis;

	public AcceptableTrustedListCheck(T result, XmlTLAnalysis tlAnalysis, LevelConstraint constraint) {
		super(result, constraint, tlAnalysis.getCountryCode());

		this.tlAnalysis = tlAnalysis;
	}

	@Override
	public boolean process() {
		return isValidConclusion(tlAnalysis.getConclusion());
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_TRUSTED_LIST_ACCEPT;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_TRUSTED_LIST_ACCEPT_ANS;
	}

	@Override
	protected String getAdditionalInfo() {
		Object[] params = new Object[] { tlAnalysis.getCountryCode() };
		return MessageFormat.format(AdditionalInfo.TRUSTED_LIST, params);
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
