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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlPCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVTS;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;

public class ValidationTimeSlidingCheck extends ChainItem<XmlPCV> {

	private final XmlVTS vts;

	public ValidationTimeSlidingCheck(I18nProvider i18nProvider, XmlPCV result, XmlVTS vts, String tokenId, LevelConstraint constraint) {
		super(i18nProvider, result, constraint, tokenId);

		this.vts = vts;
	}

	@Override
	protected boolean process() {
		return isValid(vts);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.PCV_IVTSC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.PCV_IVTSC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return vts.getConclusion().getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return vts.getConclusion().getSubIndication();
	}

}
