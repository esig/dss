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
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Checks if the ServiceDigitalIdentifier of the TrustService matches the TrustService name
 *
 */
public class TrustedCertificateMatchTrustServiceCheck extends ChainItem<XmlValidationCertificateQualification> {

	/** Trusted Service to check */
	private final TrustServiceWrapper trustService;

	/** Internal cached error status message */
	private MessageTag errorMessage = MessageTag.EMPTY;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlValidationCertificateQualification}
	 * @param trustService {@link TrustServiceWrapper}
	 * @param constraint {@link LevelConstraint}
	 */
	public TrustedCertificateMatchTrustServiceCheck(I18nProvider i18nProvider,
													XmlValidationCertificateQualification result,
													TrustServiceWrapper trustService, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

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

		List<String> possibleMatchers = new ArrayList<>();
		possibleMatchers.addAll(trustService.getTspNames());
		possibleMatchers.addAll(trustService.getTspTradeNames());
		possibleMatchers.addAll(trustService.getServiceNames());

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
