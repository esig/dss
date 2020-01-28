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
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

public class BestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpirationCheck extends ChainItem<XmlPSV> {

	private final Date controlTime;
	private final CertificateWrapper certificate;
	private final SubIndication currentTimeSubIndication;

	public BestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpirationCheck(I18nProvider i18nProvider, XmlPSV result, Date controlTime,
			CertificateWrapper certificate, SubIndication currentTimeSubIndication, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

		this.controlTime = controlTime;
		this.certificate = certificate;
		this.currentTimeSubIndication = currentTimeSubIndication;
	}

	@Override
	protected boolean process() {
		// inclusive by RFC 5280
		return controlTime.compareTo(certificate.getNotBefore()) >= 0 && controlTime.compareTo(certificate.getNotAfter()) <= 0;
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
		return currentTimeSubIndication;
	}

}
