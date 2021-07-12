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

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * Checks if the certificate is not expired
 */
public class CertificateValidityRangeCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** Validation date */
	private final Date currentTime;

	/** Certificate to check */
	private final CertificateWrapper certificate;

	/** The certificate's revocation */
	private final CertificateRevocationWrapper usedCertificateRevocation;

	/** The SubIndication if validation fails */
	private SubIndication subIndication;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param certificate {@link CertificateWrapper}
	 * @param usedCertificateRevocation {@link CertificateRevocationWrapper}
	 * @param currentTime {@link Date} validation time
	 * @param constraint {@link LevelConstraint}
	 */
	public CertificateValidityRangeCheck(I18nProvider i18nProvider, T result, CertificateWrapper certificate,
										 CertificateRevocationWrapper usedCertificateRevocation, Date currentTime, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.currentTime = currentTime;
		this.certificate = certificate;
		this.usedCertificateRevocation = usedCertificateRevocation;
	}

	@Override
	protected boolean process() {
		boolean inValidityRange = isInValidityRange();
		if (!inValidityRange) {
			subIndication = SubIndication.OUT_OF_BOUNDS_NO_POE;
			if (ValidationProcessUtils.isRevocationCheckRequired(certificate)) {
				if (usedCertificateRevocation != null && !usedCertificateRevocation.isRevoked()) {
					subIndication = SubIndication.OUT_OF_BOUNDS_NOT_REVOKED;
				}
			}
		}
		return inValidityRange;
	}

	private boolean isInValidityRange() {
		Date notBefore = certificate.getNotBefore();
		Date notAfter = certificate.getNotAfter();
		return (notBefore != null && (currentTime.compareTo(notBefore) >= 0)) && (notAfter != null && (currentTime.compareTo(notAfter) <= 0));
	}

	@Override
	protected String buildAdditionalInfo() {
		String notBeforeStr = certificate.getNotBefore() == null ? " ? " : ValidationProcessUtils.getFormattedDate(certificate.getNotBefore());
		String notAfterStr = certificate.getNotAfter() == null ? " ? " : ValidationProcessUtils.getFormattedDate(certificate.getNotAfter());
		String validationTime = ValidationProcessUtils.getFormattedDate(currentTime);
		return i18nProvider.getMessage(MessageTag.CERTIFICATE_VALIDITY, validationTime, notBeforeStr, notAfterStr);
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
		return subIndication;
	}

}
