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
import java.util.stream.Collectors;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificate;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.AcceptableTrustedListCheck;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedServiceFilter;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedServicesFilterFactory;

public class CertificateQualificationBlock extends Chain<XmlCertificate> {

	private final XmlConclusion buildingBlocksConclusion;
	private final Date validationTime;
	private final CertificateWrapper signingCertificate;
	private final List<XmlTLAnalysis> tlAnalysis;

	public CertificateQualificationBlock(I18nProvider i18nProvider, XmlConclusion buildingBlocksConclusion, Date validationTime, CertificateWrapper signingCertificate,
			List<XmlTLAnalysis> tlAnalysis) {
		super(i18nProvider, new XmlCertificate());

		this.buildingBlocksConclusion = buildingBlocksConclusion;
		this.validationTime = validationTime;
		this.signingCertificate = signingCertificate;
		this.tlAnalysis = tlAnalysis;
	}
	
	@Override
	protected MessageTag getTitle() {
		return MessageTag.CERT_QUALIFICATION;
	}

	@Override
	protected void initChain() {

		// cover incomplete cert chain / expired/ revoked certs
		ChainItem<XmlCertificate> item = firstItem = isAcceptableBuildingBlockConclusion(buildingBlocksConclusion);

		if (signingCertificate != null && signingCertificate.hasTrustedServices()) {

			List<TrustedServiceWrapper> originalTSPs = signingCertificate.getTrustedServices();
			Set<String> trustedListUrls = originalTSPs.stream().filter(t -> t.getTrustedList() != null)
					.map(t -> t.getTrustedList().getUrl()).collect(Collectors.toSet());
			Set<String> listOfTrustedListUrls = originalTSPs.stream().filter(t -> t.getListOfTrustedLists() != null)
					.map(t -> t.getListOfTrustedLists().getUrl()).collect(Collectors.toSet());

			for (String lotlURL : listOfTrustedListUrls) {
				XmlTLAnalysis lotlAnalysis = getTlAnalysis(lotlURL);
				if (lotlAnalysis != null) {
					item = item.setNextItem(isAcceptableTL(lotlAnalysis));
				}
			}

			Set<String> acceptableUrls = new HashSet<String>();
			for (String tlURL : trustedListUrls) {
				XmlTLAnalysis currentTL = getTlAnalysis(tlURL);
				if (currentTL != null) {
					AcceptableTrustedListCheck<XmlCertificate> acceptableTL = isAcceptableTL(currentTL);
					item = item.setNextItem(acceptableTL);
					if (acceptableTL.process()) {
						acceptableUrls.add(tlURL);
					}
				}
			}

			// 1. filter by service for CAQC
			TrustedServiceFilter filter = TrustedServicesFilterFactory.createFilterByUrls(acceptableUrls);
			List<TrustedServiceWrapper> acceptableServices = filter.filter(originalTSPs);

			filter = TrustedServicesFilterFactory.createFilterByCaQc();
			List<TrustedServiceWrapper> caqcServices = filter.filter(acceptableServices);

			CertQualificationAtTimeBlock certQualAtIssuanceBlock = new CertQualificationAtTimeBlock(i18nProvider, ValidationTime.CERTIFICATE_ISSUANCE_TIME,
					signingCertificate, caqcServices);
			result.getValidationCertificateQualification().add(certQualAtIssuanceBlock.execute());

			CertQualificationAtTimeBlock certQualAtSigningTimeBlock = new CertQualificationAtTimeBlock(i18nProvider, ValidationTime.VALIDATION_TIME, 
					validationTime, signingCertificate, caqcServices);
			result.getValidationCertificateQualification().add(certQualAtSigningTimeBlock.execute());

		}
	}

	private XmlTLAnalysis getTlAnalysis(String url) {
		for (XmlTLAnalysis xmlTLAnalysis : tlAnalysis) {
			if (Utils.areStringsEqual(url, xmlTLAnalysis.getURL())) {
				return xmlTLAnalysis;
			}
		}
		return null;
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
		return new AcceptableTrustedListCheck<XmlCertificate>(i18nProvider, result, xmlTLAnalysis, getFailLevelConstraint());
	}

	private ChainItem<XmlCertificate> isAcceptableBuildingBlockConclusion(XmlConclusion buildingBlocksConclusion) {
		return new AcceptableBuildingBlockConclusionCheck(i18nProvider, result, buildingBlocksConclusion, getWarnLevelConstraint());
	}

}
