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

import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;

/*
 * If best-signature-time is before the issuance date of the signing certificate, the process shall return the
 * indication FAILED with the sub-indication NOT_YET_VALID. Otherwise, the process shall return the indication
 * INDETERMINATE with the sub-indication OUT_OF_BOUNDS_NO_POE.
 */
public class BestSignatureTimeNotBeforeCertificateIssuanceCheck extends ChainItem<XmlValidationProcessLongTermData> {

	private final Date bestSignatureTime;
	private final CertificateWrapper signingCertificate;

	public BestSignatureTimeNotBeforeCertificateIssuanceCheck(XmlValidationProcessLongTermData result, Date bestSignatureTime,
			CertificateWrapper signingCertificate, LevelConstraint constraint) {
		super(result, constraint);

		this.bestSignatureTime = bestSignatureTime;
		this.signingCertificate = signingCertificate;
	}

	@Override
	protected boolean process() {
		return !bestSignatureTime.before(signingCertificate.getNotBefore());
	}

	@Override
	protected String getAdditionalInfo() {
		SimpleDateFormat sdf = new SimpleDateFormat(AdditionalInfo.DATE_FORMAT);
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		String bestSignatureTimeStr = bestSignatureTime == null ? " ? " : sdf.format(bestSignatureTime);
		return MessageFormat.format(AdditionalInfo.BEST_SIGNATURE_TIME, bestSignatureTimeStr);
	}

	@Override
	protected String getMessageTag() {
		return "TSV_IBSTAIDOSC";
	}

	@Override
	protected String getErrorMessageTag() {
		return "TSV_IBSTAIDOSC_ANS";
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NOT_YET_VALID;
	}

	@Override
	protected Indication getSuccessIndication() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getSuccessSubIndication() {
		return SubIndication.OUT_OF_BOUNDS_NO_POE;
	}

}
