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

import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateOnHoldCheck extends ChainItem<XmlSubXCV> {

	private final CertificateRevocationWrapper certificateRevocation;
	private final Date currentTime;

	public CertificateOnHoldCheck(XmlSubXCV result, CertificateRevocationWrapper certificateRevocation, Date currentTime, LevelConstraint constraint) {
		super(result, constraint);
		this.certificateRevocation = certificateRevocation;
		this.currentTime = currentTime;
	}

	@Override
	protected boolean process() {
		boolean isOnHold = (certificateRevocation != null) && !certificateRevocation.isStatus() && 
				RevocationReason.CERTIFICATE_HOLD.equals(certificateRevocation.getReason());
		if (isOnHold) {
			isOnHold = certificateRevocation.getRevocationDate() != null && currentTime.after(certificateRevocation.getRevocationDate());
		}
		return !isOnHold;
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
		return MessageTag.BBB_XCV_ISCOH;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_ISCOH_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.TRY_LATER;
	}

}
