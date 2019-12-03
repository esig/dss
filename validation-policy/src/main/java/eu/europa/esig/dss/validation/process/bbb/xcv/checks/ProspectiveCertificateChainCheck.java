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
package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.i18n.MessageTag;

public class ProspectiveCertificateChainCheck extends ChainItem<XmlXCV> {

	private final CertificateWrapper certificate;

	private final Context context;

	public ProspectiveCertificateChainCheck(XmlXCV result, CertificateWrapper certificate, Context context,
			LevelConstraint constraint) {
		super(result, constraint);
		this.certificate = certificate;
		this.context = context;
	}

	@Override
	protected boolean process() {
		return certificate.isTrusted() || certificate.isTrustedChain();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_CCCBB;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		switch (context) {
		case SIGNATURE:
			return MessageTag.BBB_XCV_CCCBB_SIG_ANS;
		case COUNTER_SIGNATURE:
			return MessageTag.BBB_XCV_CCCBB_SIG_ANS;
		case TIMESTAMP:
			return MessageTag.BBB_XCV_CCCBB_TSP_ANS;
		case REVOCATION:
			return MessageTag.BBB_XCV_CCCBB_REV_ANS;
		default:
			return MessageTag.BBB_XCV_CCCBB_ANS;
		}
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NO_CERTIFICATE_CHAIN_FOUND;
	}

}
