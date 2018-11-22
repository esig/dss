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

import java.text.MessageFormat;

import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationCertificateQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.qualification.trust.consistency.TrustedServiceChecker;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ServiceConsistencyCheck extends ChainItem<XmlValidationCertificateQualification> {

	private final TrustedServiceWrapper trustedService;

	private MessageTag errorMessage;

	public ServiceConsistencyCheck(XmlValidationCertificateQualification result, TrustedServiceWrapper trustedService, LevelConstraint constraint) {
		super(result, constraint);

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
	protected String getAdditionalInfo() {
		if (trustedService != null) {
			Object[] params = new Object[] { trustedService.getServiceName() };
			return MessageFormat.format(AdditionalInfo.TRUST_SERVICE_NAME, params);
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
