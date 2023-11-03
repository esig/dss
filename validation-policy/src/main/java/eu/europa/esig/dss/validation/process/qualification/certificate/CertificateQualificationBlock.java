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

import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificate;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.AcceptableListOfTrustedListsCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.AcceptableTrustedListCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.AcceptableTrustedListPresenceCheck;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustServiceFilter;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustServicesFilterFactory;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * This class verifies the final qualification of a certificate,
 * processing its validation at issuance and validation time
 *
 */
public class CertificateQualificationBlock extends Chain<XmlCertificate> {

	/** Certificate's BasicBuildingBlock's conclusion */
	private final XmlConclusion buildingBlocksConclusion;

	/** Validation time */
	private final Date validationTime;

	/** The certificate to determine qualification for */
	private final CertificateWrapper signingCertificate;

	/** List of validation results for all Trusted Lists */
	private final List<XmlTLAnalysis> tlAnalysis;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param buildingBlocksConclusion {@link XmlConclusion} of BBB for the validating certificate
	 * @param validationTime {@link Date} validation time
	 * @param signingCertificate {@link CertificateWrapper} to be validated
	 * @param tlAnalysis a list of {@link XmlTLAnalysis}
	 */
	public CertificateQualificationBlock(I18nProvider i18nProvider, XmlConclusion buildingBlocksConclusion,
										 Date validationTime, CertificateWrapper signingCertificate,
										 List<XmlTLAnalysis> tlAnalysis) {
		super(i18nProvider, new XmlCertificate());
		Objects.requireNonNull(validationTime, "The validationTime shall be provided!");
		Objects.requireNonNull(signingCertificate, "The signingCertificate shall be provided!");
		
		result.setId(signingCertificate.getId());

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

		if (signingCertificate.isTrustedListReached()) {

			List<TrustServiceWrapper> originalTSPs = signingCertificate.getTrustServices();
			
			Set<String> listOfTrustedListUrls = originalTSPs.stream().filter(t -> t.getListOfTrustedLists() != null)
					.map(t -> t.getListOfTrustedLists().getUrl()).collect(Collectors.toSet());

			Set<String> acceptableLOTLUrls = new HashSet<>();
			for (String lotlURL : listOfTrustedListUrls) {
				XmlTLAnalysis lotlAnalysis = getTlAnalysis(lotlURL);
				if (lotlAnalysis != null) {
					AcceptableListOfTrustedListsCheck<XmlCertificate> acceptableLOTL = isAcceptableLOTL(lotlAnalysis);
					item = item.setNextItem(acceptableLOTL);
					if (acceptableLOTL.process()) {
						acceptableLOTLUrls.add(lotlURL);
					}
				}
			}
			
			// filter TLs with a found valid set of LOTLs (if assigned)
			Set<String> trustedListUrls = originalTSPs.stream().filter(t -> t.getTrustedList() != null && 
					(t.getListOfTrustedLists() == null || acceptableLOTLUrls.contains(t.getListOfTrustedLists().getUrl())) )
					.map(t -> t.getTrustedList().getUrl()).collect(Collectors.toSet());

			Set<String> acceptableTLUrls = new HashSet<>();
			if (Utils.isCollectionNotEmpty(trustedListUrls)) {
				for (String tlURL : trustedListUrls) {
					XmlTLAnalysis currentTL = getTlAnalysis(tlURL);
					if (currentTL != null) {
						AcceptableTrustedListCheck<XmlCertificate> acceptableTL = isAcceptableTL(currentTL);
						item = item.setNextItem(acceptableTL);
						if (acceptableTL.process()) {
							acceptableTLUrls.add(tlURL);
						}
					}
				}
			}
			
			item = item.setNextItem(isAcceptableTLPresent(acceptableTLUrls));
			
			if (Utils.isCollectionNotEmpty(acceptableTLUrls)) {

				// 1. filter by service for CAQC
				TrustServiceFilter filter = TrustServicesFilterFactory.createFilterByUrls(acceptableTLUrls);
				List<TrustServiceWrapper> acceptableServices = filter.filter(originalTSPs);

				CertQualificationAtTimeBlock certQualAtIssuanceBlock = new CertQualificationAtTimeBlock(i18nProvider, ValidationTime.CERTIFICATE_ISSUANCE_TIME,
						signingCertificate, acceptableServices);
				result.getValidationCertificateQualification().add(certQualAtIssuanceBlock.execute());

				CertQualificationAtTimeBlock certQualAtSigningTimeBlock = new CertQualificationAtTimeBlock(i18nProvider, ValidationTime.VALIDATION_TIME,
						validationTime, signingCertificate, acceptableServices);
				result.getValidationCertificateQualification().add(certQualAtSigningTimeBlock.execute());
			
			}
		}
	}

	private XmlTLAnalysis getTlAnalysis(String url) {
		if (Utils.isCollectionNotEmpty(tlAnalysis)) {
			for (XmlTLAnalysis xmlTLAnalysis : tlAnalysis) {
				if (Utils.areStringsEqual(url, xmlTLAnalysis.getURL())) {
					return xmlTLAnalysis;
				}
			}
		}
		return null;
	}

	@Override
	protected void addAdditionalInfo() {
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

	private AcceptableListOfTrustedListsCheck<XmlCertificate> isAcceptableLOTL(XmlTLAnalysis xmlLOTLAnalysis) {
		return new AcceptableListOfTrustedListsCheck<>(i18nProvider, result, xmlLOTLAnalysis, getWarnLevelConstraint());
	}

	private AcceptableTrustedListCheck<XmlCertificate> isAcceptableTL(XmlTLAnalysis xmlTLAnalysis) {
		return new AcceptableTrustedListCheck<>(i18nProvider, result, xmlTLAnalysis, getWarnLevelConstraint());
	}

	private ChainItem<XmlCertificate> isAcceptableTLPresent(Set<String> acceptableUrls) {
		return new AcceptableTrustedListPresenceCheck<>(i18nProvider, result, acceptableUrls, getFailLevelConstraint());
	}

	private ChainItem<XmlCertificate> isAcceptableBuildingBlockConclusion(XmlConclusion buildingBlocksConclusion) {
		return new AcceptableBuildingBlockConclusionCheck(i18nProvider, result, buildingBlocksConclusion, getWarnLevelConstraint());
	}

}
