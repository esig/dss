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

import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.validation.policy.SubContext;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class RevocationDateAfterBestSignatureTimeCheck extends ChainItem<XmlValidationProcessLongTermData> {

	private final CertificateWrapper certificate;
	private final Date bestSignatureTime;
	private final SubContext subContext;

	public RevocationDateAfterBestSignatureTimeCheck(XmlValidationProcessLongTermData result, CertificateWrapper certificate, Date bestSignatureTime,
			LevelConstraint constraint, SubContext subContext) {
		super(result, constraint);

		this.certificate = certificate;
		this.bestSignatureTime = bestSignatureTime;
		this.subContext = subContext;
	}

	@Override
	protected boolean process() {
		RevocationWrapper revocationData = certificate.getLatestRevocationData();
		Date revocationDate = revocationData.getRevocationDate();
		// revocation date can be null in case of unknown status
		return revocationDate != null && revocationDate.after(bestSignatureTime);
	}

	@Override
	protected String getAdditionalInfo() {
		SimpleDateFormat sdf = new SimpleDateFormat(AdditionalInfo.DATE_FORMAT);
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		String bestSignatureTimeStr = bestSignatureTime == null ? " ? " : sdf.format(bestSignatureTime);
		return MessageFormat.format(AdditionalInfo.BEST_SIGNATURE_TIME, bestSignatureTimeStr);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ADEST_IRTPTBST;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ADEST_IRTPTBST_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		if (SubContext.SIGNING_CERT.equals(subContext))
			return SubIndication.REVOKED_NO_POE;
		else
			return SubIndication.REVOKED_CA_NO_POE;
	}

}
