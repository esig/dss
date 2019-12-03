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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks;

import java.util.Date;

import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;

public class BestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpirationCheck extends ChainItem<XmlPSV> {

	private final Date bestSignatureTime;
	private final CertificateWrapper signingCertificate;

	public BestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpirationCheck(I18nProvider i18nProvider, XmlPSV result, Date bestSignatureTime,
			CertificateWrapper signingCertificate, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

		this.bestSignatureTime = bestSignatureTime;
		this.signingCertificate = signingCertificate;
	}

	@Override
	protected boolean process() {
		return bestSignatureTime.after(signingCertificate.getNotBefore()) && bestSignatureTime.before(signingCertificate.getNotAfter());
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.TSV_ISCNVABST;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.TSV_ISCNVABST_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.OUT_OF_BOUNDS_NO_POE;
	}

}
