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
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.trust.consistency.TrustedServiceChecker;

public class ServiceConsistencyCheck extends ChainItem<XmlValidationCertificateQualification> {

	private final TrustedServiceWrapper trustedService;

	private MessageTag errorMessage;

	public ServiceConsistencyCheck(I18nProvider i18nProvider, XmlValidationCertificateQualification result, 
			TrustedServiceWrapper trustedService, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

		this.trustedService = trustedService;
	}

	@Override
	protected boolean process() {

		if (trustedService == null) {

			errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS0;
			return false;

		} else {

			if (!TrustedServiceChecker.isQCStatementConsistent(trustedService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS1;
				return false;
			}

			if (!TrustedServiceChecker.isLegalPersonConsistent(trustedService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS2;
				return false;
			}

			if (!TrustedServiceChecker.isQSCDConsistent(trustedService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS3;
				return false;
			}

			if (!TrustedServiceChecker.isQSCDStatusAsInCertConsistent(trustedService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS3A;
				return false;
			}

			if (!TrustedServiceChecker.isUsageConsistent(trustedService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS4;
				return false;
			}

			if (!TrustedServiceChecker.isPreEIDASConsistent(trustedService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS5;
				return false;
			}

			if (!TrustedServiceChecker.isQualifierAndAdditionalServiceInfoConsistent(trustedService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS6;
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
		if (trustedService != null) {
			return i18nProvider.getMessage(MessageTag.TRUST_SERVICE_NAME, trustedService.getServiceNames().get(0));
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
