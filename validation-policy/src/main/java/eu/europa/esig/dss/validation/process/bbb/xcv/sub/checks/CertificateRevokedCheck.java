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
package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.validation.policy.SubContext;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateRevocationWrapper;
import eu.europa.esig.dss.x509.crl.CRLReasonEnum;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateRevokedCheck extends ChainItem<XmlSubXCV> {

	private final CertificateRevocationWrapper certificateRevocation;
	private final Date currentTime;
	private final SubContext subContext;

	public CertificateRevokedCheck(XmlSubXCV result, CertificateRevocationWrapper certificateRevocation, Date currentTime, 
			LevelConstraint constraint, SubContext subContext) {
		super(result, constraint);
		this.certificateRevocation = certificateRevocation;
		this.currentTime = currentTime;
		this.subContext = subContext;
	}

	@Override
	protected boolean process() {
		boolean isRevoked = (certificateRevocation != null) && !certificateRevocation.isStatus() && 
				!CRLReasonEnum.certificateHold.name().equals(certificateRevocation.getReason());
		if (isRevoked) {
			isRevoked = certificateRevocation.getRevocationDate() != null && currentTime.after(certificateRevocation.getRevocationDate());
		}
		return !isRevoked;
	}

	@Override
	protected String getAdditionalInfo() {
		if (certificateRevocation != null && certificateRevocation.getRevocationDate() != null) {
			SimpleDateFormat sdf = new SimpleDateFormat(AdditionalInfo.DATE_FORMAT);
			sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
			String revocationDateStr = sdf.format(certificateRevocation.getRevocationDate());
			Object[] params = new Object[] { certificateRevocation.getReason(), revocationDateStr };
			return MessageFormat.format(AdditionalInfo.REVOCATION, params);
		}
		return null;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_ISCR;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_ISCR_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		if (SubContext.SIGNING_CERT.equals(subContext)) {
			return SubIndication.REVOKED_NO_POE;
		} else {
			return SubIndication.REVOKED_CA_NO_POE;
		}
	}

}
