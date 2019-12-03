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
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.i18n.MessageTag;

public class CertificateExpirationCheck extends ChainItem<XmlSubXCV> {

	private final Date currentTime;
	private final CertificateWrapper certificate;

	public CertificateExpirationCheck(XmlSubXCV result, CertificateWrapper certificate, Date currentTime, LevelConstraint constraint) {
		super(result, constraint);
		this.currentTime = currentTime;
		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		Date notBefore = certificate.getNotBefore();
		Date notAfter = certificate.getNotAfter();
		return (notBefore != null && (currentTime.compareTo(notBefore) >= 0))
				&& (notAfter != null && (currentTime.compareTo(notAfter) <= 0));
	}

	@Override
	protected String getAdditionalInfo() {
		SimpleDateFormat sdf = new SimpleDateFormat(AdditionalInfo.DATE_FORMAT);
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		String notBeforeStr = certificate.getNotBefore() == null ? " ? " : sdf.format(certificate.getNotBefore());
		String notAfterStr = certificate.getNotAfter() == null ? " ? " : sdf.format(certificate.getNotAfter());
		Object[] params = new Object[] { notBeforeStr, notAfterStr };
		return MessageFormat.format(AdditionalInfo.CERTIFICATE_VALIDITY, params);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_ICTIVRSC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_ICTIVRSC_ANS;
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
