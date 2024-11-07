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
package eu.europa.esig.dss.validation.process.qualification.timestamp;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationTimestampQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationTimestampQualificationAtTime;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.AcceptableListOfTrustedListsCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.AcceptableTrustedListCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.AcceptableTrustedListPresenceCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.TrustedListReachedForCertificateChainCheck;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustServiceFilter;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustServicesFilterFactory;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The class performs a qualification verification for a timestamp
 */
public class TimestampQualificationBlock extends Chain<XmlValidationTimestampQualification> {

	/** The timestamp to be validated */
	private final TimestampWrapper timestamp;

	/** The list of all TL analyses */
	private final List<XmlTLAnalysis> tlAnalysis;

	/** Contains list of all POEs */
	private final POEExtraction poe;

	/** The list of related LOTL/TL analyses */
	private final List<XmlTLAnalysis> relatedTLAnalyses = new ArrayList<>();

	/** The determined timestamp qualification */
	private TimestampQualification tstQualification = TimestampQualification.NA;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param timestamp {@link TimestampWrapper} qualification of which will be verified
	 * @param tlAnalysis a list of performed {@link XmlTLAnalysis}
	 * @param poe {@link POEExtraction}
	 */
	public TimestampQualificationBlock(I18nProvider i18nProvider, TimestampWrapper timestamp,
									   List<XmlTLAnalysis> tlAnalysis, POEExtraction poe) {
		super(i18nProvider, new XmlValidationTimestampQualification());
		this.timestamp = timestamp;
		this.tlAnalysis = tlAnalysis;
		this.poe = poe;
	}
	
	@Override
	protected MessageTag getTitle() {
		return MessageTag.TST_QUALIFICATION;
	}

	@Override
	protected void initChain() {
		CertificateWrapper signingCertificate = timestamp.getSigningCertificate();

		ChainItem<XmlValidationTimestampQualification> item = firstItem = isTrustedListReachedForCertificateChain(signingCertificate);
		
		if (signingCertificate != null && signingCertificate.isTrustedListReached()) {

			List<TrustServiceWrapper> originalTSPs = signingCertificate.getTrustServices();
			
			Set<String> listOfTrustedListUrls = originalTSPs.stream().filter(t -> t.getListOfTrustedLists() != null)
					.map(t -> t.getListOfTrustedLists().getUrl()).collect(Collectors.toSet());

			Set<String> acceptableLOTLUrls = new HashSet<>();
			for (String lotlURL : listOfTrustedListUrls) {
				XmlTLAnalysis lotlAnalysis = getTlAnalysis(lotlURL);
				if (lotlAnalysis != null) {
					relatedTLAnalyses.add(lotlAnalysis);

					AcceptableListOfTrustedListsCheck<XmlValidationTimestampQualification> acceptableLOTL = isAcceptableLOTL(lotlAnalysis);
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
						relatedTLAnalyses.add(currentTL);

						AcceptableTrustedListCheck<XmlValidationTimestampQualification> acceptableTL = isAcceptableTL(currentTL);
						item = item.setNextItem(acceptableTL);
						if (acceptableTL.process()) {
							acceptableTLUrls.add(tlURL);
						}
					}
				}
			}
			
			item = item.setNextItem(isAcceptableTLPresent(acceptableTLUrls));
			
			if (Utils.isCollectionNotEmpty(acceptableTLUrls)) {

				TrustServiceFilter filter = TrustServicesFilterFactory.createFilterByUrls(acceptableTLUrls);
				List<TrustServiceWrapper> acceptableServices = filter.filter(originalTSPs);

                TimestampQualificationAtTimeBlock tstQualificationAtGenerationTimeBlock = new TimestampQualificationAtTimeBlock(
                        i18nProvider, ValidationTime.TIMESTAMP_GENERATION_TIME, timestamp, acceptableServices);
                XmlValidationTimestampQualificationAtTime conclusionAtGenerationTime = tstQualificationAtGenerationTimeBlock.execute();
                result.getValidationTimestampQualificationAtTime().add(conclusionAtGenerationTime);

				Date timestampPOE = poe.getLowestPOETime(timestamp.getId());
				TimestampQualificationAtTimeBlock tstQualificationAtPOETimeBlock = new TimestampQualificationAtTimeBlock(
						i18nProvider, ValidationTime.TIMESTAMP_POE_TIME, timestampPOE, timestamp, acceptableServices);
                XmlValidationTimestampQualificationAtTime conclusionAtPOETime = tstQualificationAtPOETimeBlock.execute();
                result.getValidationTimestampQualificationAtTime().add(conclusionAtPOETime);

                determineFinalQualification(conclusionAtGenerationTime.getTimestampQualification(), conclusionAtPOETime.getTimestampQualification());
				
			}
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

    private void determineFinalQualification(TimestampQualification qualAtGenerationTime, TimestampQualification qualAtPOETime) {
        if (TimestampQualification.QTSA == qualAtGenerationTime && TimestampQualification.QTSA == qualAtPOETime) {
			tstQualification = TimestampQualification.QTSA;
        } else {
			tstQualification = TimestampQualification.TSA;
        }
    }

	@Override
	protected void addAdditionalInfo() {
		setIndication();
		setTimestampQualification();
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

	private void setTimestampQualification() {
		result.setTimestampQualification(tstQualification);
	}

	@Override
	protected void collectAdditionalMessages(XmlConclusion conclusion) {
		for (XmlValidationTimestampQualificationAtTime tstQualAtTime : result.getValidationTimestampQualificationAtTime()) {
			collectAllMessages(conclusion, tstQualAtTime.getConclusion());
		}
		for (XmlTLAnalysis relatedTLAnalysis : relatedTLAnalyses) {
			collectAllMessages(conclusion, relatedTLAnalysis.getConclusion());
		}
	}

	private ChainItem<XmlValidationTimestampQualification> isTrustedListReachedForCertificateChain(CertificateWrapper signingCertificate) {
		return new TrustedListReachedForCertificateChainCheck<>(i18nProvider, result, signingCertificate, getFailLevelConstraint());
	}

	private AcceptableListOfTrustedListsCheck<XmlValidationTimestampQualification> isAcceptableLOTL(XmlTLAnalysis xmlLOTLAnalysis) {
		return new AcceptableListOfTrustedListsCheck<>(i18nProvider, result, xmlLOTLAnalysis, getWarnLevelConstraint());
	}

	private AcceptableTrustedListCheck<XmlValidationTimestampQualification> isAcceptableTL(XmlTLAnalysis xmlTLAnalysis) {
		return new AcceptableTrustedListCheck<>(i18nProvider, result, xmlTLAnalysis, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationTimestampQualification> isAcceptableTLPresent(Set<String> acceptableUrls) {
		return new AcceptableTrustedListPresenceCheck<>(i18nProvider, result, acceptableUrls, getFailLevelConstraint());
	}

}
