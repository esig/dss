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
package eu.europa.esig.dss.validation.process.qualification.certificate;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.jaxb.detailedreport.XmlCertificate;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlTLAnalysis;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ValidationTime;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessDefinition;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.AcceptableTrustedListCheck;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedServiceFilter;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedServicesFilterFactory;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class CertificateQualificationBlock extends Chain<XmlCertificate> {

	private final XmlConclusion buildingBlocksConclusion;
	private final Date validationTime;
	private final CertificateWrapper signingCertificate;
	private final List<XmlTLAnalysis> tlAnalysis;
	private final String lotlCountryCode;

	public CertificateQualificationBlock(XmlConclusion buildingBlocksConclusion, Date validationTime, CertificateWrapper signingCertificate,
			List<XmlTLAnalysis> tlAnalysis, String lotlCountryCode) {
		super(new XmlCertificate());
		result.setTitle(ValidationProcessDefinition.CERT_QUALIFICATION.getTitle());

		this.buildingBlocksConclusion = buildingBlocksConclusion;
		this.validationTime = validationTime;
		this.signingCertificate = signingCertificate;
		this.tlAnalysis = tlAnalysis;
		this.lotlCountryCode = lotlCountryCode;
	}

	@Override
	protected void initChain() {

		// cover incomplete cert chain / expired/ revoked certs
		ChainItem<XmlCertificate> item = firstItem = isAcceptableBuildingBlockConclusion(buildingBlocksConclusion);

		if (signingCertificate != null && signingCertificate.hasTrustedServices()) {

			XmlTLAnalysis lotlAnalysis = getTlAnalysis(lotlCountryCode);
			if (lotlAnalysis != null) {
				item = item.setNextItem(isAcceptableTL(lotlAnalysis));
			}

			Set<String> acceptableCountries = new HashSet<String>();

			List<TrustedServiceWrapper> originalTSPs = signingCertificate.getTrustedServices();
			Set<String> countryCodes = getCountryCodes(originalTSPs);
			for (String countryCode : countryCodes) {
				XmlTLAnalysis currentTL = getTlAnalysis(countryCode);
				if (currentTL != null) {
					AcceptableTrustedListCheck<XmlCertificate> acceptableTL = isAcceptableTL(currentTL);
					item = item.setNextItem(acceptableTL);
					if (acceptableTL.process()) {
						acceptableCountries.add(countryCode);
					}
				}
			}

			// 1. filter by service for CAQC
			TrustedServiceFilter filter = TrustedServicesFilterFactory.createFilterByCountries(acceptableCountries);
			List<TrustedServiceWrapper> acceptableServices = filter.filter(originalTSPs);

			filter = TrustedServicesFilterFactory.createFilterByCaQc();
			List<TrustedServiceWrapper> caqcServices = filter.filter(acceptableServices);

			CertQualificationAtTimeBlock certQualAtIssuanceBlock = new CertQualificationAtTimeBlock(ValidationTime.CERTIFICATE_ISSUANCE_TIME,
					signingCertificate, caqcServices);
			result.getValidationCertificateQualification().add(certQualAtIssuanceBlock.execute());

			CertQualificationAtTimeBlock certQualAtSigningTimeBlock = new CertQualificationAtTimeBlock(ValidationTime.VALIDATION_TIME, validationTime,
					signingCertificate, caqcServices);
			result.getValidationCertificateQualification().add(certQualAtSigningTimeBlock.execute());

		}
	}

	private XmlTLAnalysis getTlAnalysis(String countryCode) {
		for (XmlTLAnalysis xmlTLAnalysis : tlAnalysis) {
			if (Utils.areStringsEqual(countryCode, xmlTLAnalysis.getCountryCode())) {
				return xmlTLAnalysis;
			}
		}
		return null;
	}

	private Set<String> getCountryCodes(List<TrustedServiceWrapper> caqcServices) {
		Set<String> countryCodes = new HashSet<String>();
		for (TrustedServiceWrapper trustedServiceWrapper : caqcServices) {
			countryCodes.add(trustedServiceWrapper.getCountryCode());
		}
		return countryCodes;
	}

	@Override
	protected void addAdditionalInfo() {
		collectErrorsWarnsInfos();
		setIndication();
	}

	private void setIndication() {
		XmlConclusion conclusion = result.getConclusion();
		if (conclusion != null) {
			if (Utils.isCollectionNotEmpty(conclusion.getErrors())) {
				conclusion.setIndication(Indication.FAILED);
			} else if (Utils.isCollectionNotEmpty(conclusion.getWarnings())) {
				conclusion.setIndication(Indication.INDETERMINATE);
			} else {
				conclusion.setIndication(Indication.PASSED);
			}
		}
	}

	private AcceptableTrustedListCheck<XmlCertificate> isAcceptableTL(XmlTLAnalysis xmlTLAnalysis) {
		return new AcceptableTrustedListCheck<XmlCertificate>(result, xmlTLAnalysis, getFailLevelConstraint());
	}

	private ChainItem<XmlCertificate> isAcceptableBuildingBlockConclusion(XmlConclusion buildingBlocksConclusion) {
		return new AcceptableBuildingBlockConclusionCheck(result, buildingBlocksConclusion, getWarnLevelConstraint());
	}

}
