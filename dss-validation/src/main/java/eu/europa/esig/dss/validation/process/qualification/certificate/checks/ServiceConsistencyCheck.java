/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.qualification.certificate.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.trust.consistency.TrustServiceChecker;

/**
 * Checks if the Trusted Service is consistent
 *
 */
public class ServiceConsistencyCheck extends ChainItem<XmlValidationCertificateQualification> {

	/** Trusted Service to check */
	private final TrustServiceWrapper trustService;

	/** Internal cached error message, if applicable */
	private MessageTag errorMessage;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlValidationCertificateQualification}
	 * @param trustService {@link TrustServiceWrapper}
	 * @param constraint {@link LevelConstraint}
	 */
	public ServiceConsistencyCheck(I18nProvider i18nProvider, XmlValidationCertificateQualification result, 
			TrustServiceWrapper trustService, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

		this.trustService = trustService;
	}

	@Override
	protected boolean process() {

		if (trustService == null) {

			errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS0;
			return false;

		} else {

			if (!TrustServiceChecker.isQCStatementConsistent(trustService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS1;
				return false;
			}

			if (!TrustServiceChecker.isQSCDConsistent(trustService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS3;
				return false;
			}

			if (!TrustServiceChecker.isQSCDStatusAsInCertConsistent(trustService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS3A;
				return false;
			}

			if (!TrustServiceChecker.isPostEIDASQSCDConsistent(trustService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS3B;
				return false;
			}

			if (!TrustServiceChecker.isQualifiersListKnownConsistent(trustService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS3C;
				return false;
			}

			if (!TrustServiceChecker.isUsageConsistent(trustService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS4;
				return false;
			}

			if (!TrustServiceChecker.isPreEIDASStatusConsistent(trustService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS5;
				return false;
			}

			if (!TrustServiceChecker.isPreEIDASQualifierAndAdditionalServiceInfoConsistent(trustService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS6;
				return false;
			}

			if (!TrustServiceChecker.isQualifierAndAdditionalServiceInfoConsistent(trustService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS7;
				return false;
			}

			return true;
		}
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_TL_SERV_CONS;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return errorMessage;
	}

	@Override
	protected String buildAdditionalInfo() {
		if (trustService != null) {
			return i18nProvider.getMessage(MessageTag.TRUST_SERVICE_NAME, trustService.getServiceNames().get(0));
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
