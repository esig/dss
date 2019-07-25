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

import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;

public class TrustedCertificateMatchTrustServiceCheck extends ChainItem<XmlValidationCertificateQualification> {

	private final TrustedServiceWrapper trustService;
	private MessageTag errorMessage = MessageTag.EMPTY;

	public TrustedCertificateMatchTrustServiceCheck(XmlValidationCertificateQualification result, TrustedServiceWrapper trustService,
			LevelConstraint constraint) {
		super(result, constraint);

		this.trustService = trustService;
	}

	@Override
	protected boolean process() {

		CertificateWrapper trustedCert = trustService.getServiceDigitalIdentifier();
		if (trustedCert == null) {
			errorMessage = MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS0;
			return false;
		}

		String organizationName = trustedCert.getOrganizationName();
		if (Utils.isStringBlank(organizationName)) {
			errorMessage = MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1;
			return false;
		}

		if (!isMatch(trustedCert)) {
			errorMessage = MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2;
			return false;
		}

		return true;
	}

	private boolean isMatch(CertificateWrapper trustedCert) {

		List<String> candidates = Arrays.asList(trustedCert.getOrganizationName(), trustedCert.getCommonName(), trustedCert.getOrganizationalUnit(),
				trustedCert.getCertificateDN());
		List<String> possibleMatchers = Arrays.asList(trustService.getTspName(), trustService.getServiceName());

		for (String candidate : candidates) {
			if (Utils.isStringBlank(candidate)) {
				continue;
			}

			for (String matcher : possibleMatchers) {
				if (Utils.areStringsEqualIgnoreCase(candidate, matcher)) {
					return true;
				}
			}
		}

		return false;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return errorMessage;
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
