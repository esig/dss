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

import java.util.Date;

import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.TimeConstraint;
import eu.europa.esig.dss.policy.jaxb.ValueConstraint;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessDefinition;
import eu.europa.esig.dss.validation.process.qualification.trust.checks.TLFreshnessCheck;
import eu.europa.esig.dss.validation.process.qualification.trust.checks.TLNotExpiredCheck;
import eu.europa.esig.dss.validation.process.qualification.trust.checks.TLVersionCheck;
import eu.europa.esig.dss.validation.process.qualification.trust.checks.TLWellSignedCheck;

public class TLValidationBlock extends Chain<XmlTLAnalysis> {

	private final XmlTrustedList currentTL;
	private final Date currentTime;
	private final ValidationPolicy policy;

	public TLValidationBlock(XmlTrustedList currentTL, Date currentTime, ValidationPolicy policy) {
		super(new XmlTLAnalysis());

		result.setTitle(ValidationProcessDefinition.TL.getTitle() + " " + currentTL.getCountryCode());
		result.setCountryCode(currentTL.getCountryCode());

		this.currentTL = currentTL;
		this.currentTime = currentTime;
		this.policy = policy;
	}

	@Override
	protected void initChain() {

		ChainItem<XmlTLAnalysis> item = firstItem = tlFreshness();

		if (!isLastTL()) {
			item = item.setNextItem(tlNotExpired());
		}

		item = item.setNextItem(tlVersion());

		item = item.setNextItem(tlWellSigned());

	}

	private boolean isLastTL() {
		return currentTL.getNextUpdate() == null;
	}

	@Override
	protected void addAdditionalInfo() {
		collectErrorsWarnsInfos();
	}

	private ChainItem<XmlTLAnalysis> tlFreshness() {
		TimeConstraint constraint = policy.getTLFreshnessConstraint();
		return new TLFreshnessCheck(result, currentTL, currentTime, constraint);
	}

	private ChainItem<XmlTLAnalysis> tlNotExpired() {
		LevelConstraint constraint = policy.getTLNotExpiredConstraint();
		return new TLNotExpiredCheck(result, currentTL, currentTime, constraint);
	}

	private ChainItem<XmlTLAnalysis> tlVersion() {
		ValueConstraint constraint = policy.getTLVersionConstraint();
		return new TLVersionCheck(result, currentTL, currentTime, constraint);
	}

	private ChainItem<XmlTLAnalysis> tlWellSigned() {
		LevelConstraint constraint = policy.getTLWellSignedConstraint();
		return new TLWellSignedCheck(result, currentTL, constraint);
	}

}
