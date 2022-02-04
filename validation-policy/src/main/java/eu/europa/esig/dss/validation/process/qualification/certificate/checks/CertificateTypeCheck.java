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
package eu.europa.esig.dss.validation.process.qualification.certificate.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.enumerations.CertificateType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks if the certificate type has been identified at the given time
 *
 */
public class CertificateTypeCheck extends ChainItem<XmlValidationCertificateQualification> {

	/** The CertificateType in question */
	private final CertificateType type;

	/** The used validation time */
	private final ValidationTime validationTime;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlValidationCertificateQualification}
	 * @param type {@link CertificateType}
	 * @param validationTime {@link ValidationTime}
	 * @param constraint {@link LevelConstraint}
	 */
	public CertificateTypeCheck(I18nProvider i18nProvider, XmlValidationCertificateQualification result,
								CertificateType type, ValidationTime validationTime, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

		this.type = type;
		this.validationTime = validationTime;
	}

	@Override
	protected boolean process() {
		return CertificateType.UNKNOWN != type;
	}

	@Override
	protected MessageTag getMessageTag() {
		switch (validationTime) {
		case BEST_SIGNATURE_TIME:
			return MessageTag.QUAL_CERT_TYPE_AT_ST;
		case CERTIFICATE_ISSUANCE_TIME:
			return MessageTag.QUAL_CERT_TYPE_AT_CC;
		case VALIDATION_TIME:
			return MessageTag.QUAL_CERT_TYPE_AT_VT;
		default:
			throw new IllegalArgumentException("Unsupported time " + validationTime);
		}
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		switch (validationTime) {
		case BEST_SIGNATURE_TIME:
			return MessageTag.QUAL_CERT_TYPE_AT_ST_ANS;
		case CERTIFICATE_ISSUANCE_TIME:
			return MessageTag.QUAL_CERT_TYPE_AT_CC_ANS;
		case VALIDATION_TIME:
			return MessageTag.QUAL_CERT_TYPE_AT_VT_ANS;
		default:
			throw new IllegalArgumentException("Unsupported time " + validationTime);
		}
	}

	@Override
	protected String buildAdditionalInfo() {
		if (CertificateType.UNKNOWN != type) {
			return i18nProvider.getMessage(MessageTag.CERTIFICATE_TYPE, type.getLabel());
		}
		return null;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}

}
