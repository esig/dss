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
package eu.europa.esig.dss.validation.process.qualification.timestamp;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationTimestampQualification;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.GrantedStatusCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.AcceptableTrustedListCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.CertificatePathTrustedCheck;
import eu.europa.esig.dss.validation.process.qualification.timestamp.checks.GrantedStatusAtProductionTimeCheck;
import eu.europa.esig.dss.validation.process.qualification.timestamp.checks.QTSTCheck;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedServiceFilter;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedServicesFilterFactory;

public class TimestampQualificationBlock extends Chain<XmlValidationTimestampQualification> {

	private final TimestampWrapper timestamp;
	private final List<XmlTLAnalysis> tlAnalysis;

	private TimestampQualification tstQualif = TimestampQualification.NA;

	public TimestampQualificationBlock(I18nProvider i18nProvider, TimestampWrapper timestamp, List<XmlTLAnalysis> tlAnalysis) {
		super(i18nProvider, new XmlValidationTimestampQualification());
		this.timestamp = timestamp;
		this.tlAnalysis = tlAnalysis;
	}
	
	@Override
	protected MessageTag getTitle() {
		return MessageTag.TST_QUALIFICATION;
	}

	@Override
	protected void initChain() {
		CertificateWrapper signingCertificate = timestamp.getSigningCertificate();

		ChainItem<XmlValidationTimestampQualification> item = firstItem = certificatePathTrusted(signingCertificate);
		
		if (signingCertificate != null && signingCertificate.hasTrustedServices()) {

			List<TrustedServiceWrapper> originalTSPs = signingCertificate.getTrustedServices();
			Set<String> trustedListUrls = originalTSPs.stream().filter(t -> t.getTrustedList() != null).map(t -> t.getTrustedList().getUrl())
					.collect(Collectors.toSet());
			Set<String> listOfTrustedListUrls = originalTSPs.stream().filter(t -> t.getListOfTrustedLists() != null)
					.map(t -> t.getListOfTrustedLists().getUrl()).collect(Collectors.toSet());

			for (String lotlURL : listOfTrustedListUrls) {
				XmlTLAnalysis lotlAnalysis = getTlAnalysis(lotlURL);
				if (lotlAnalysis != null) {
					item = item.setNextItem(isAcceptableTL(lotlAnalysis));
				}
			}

			Set<String> acceptableUrls = new HashSet<>();
			for (String tlURL : trustedListUrls) {
				XmlTLAnalysis currentTL = getTlAnalysis(tlURL);
				if (currentTL != null) {
					AcceptableTrustedListCheck<XmlValidationTimestampQualification> acceptableTL = isAcceptableTL(currentTL);
					item = item.setNextItem(acceptableTL);
					if (acceptableTL.process()) {
						acceptableUrls.add(tlURL);
					}
				}
			}

			// 1. filter by service for QTST
			TrustedServiceFilter filter = TrustedServicesFilterFactory.createFilterByUrls(acceptableUrls);
			List<TrustedServiceWrapper> acceptableServices = filter.filter(originalTSPs);

			filter = TrustedServicesFilterFactory.createFilterByQTST();
			List<TrustedServiceWrapper> qtstServices = filter.filter(acceptableServices);

			item = item.setNextItem(hasQTST(qtstServices));

			// 2. filter by granted
			filter = TrustedServicesFilterFactory.createFilterByGranted();
			List<TrustedServiceWrapper> grantedServices = filter.filter(qtstServices);

			item = item.setNextItem(hasGrantedStatus(grantedServices));

			// 3. filter by date (generation time)
			filter = TrustedServicesFilterFactory.createFilterByDate(timestamp.getProductionTime());
			List<TrustedServiceWrapper> grantedAtDateServices = filter.filter(grantedServices);

			item = item.setNextItem(hasGrantedStatusAtDate(grantedAtDateServices));

			if (grantedAtDateServices.size() > 0) {
				tstQualif = TimestampQualification.QTSA;
			} else {
				tstQualif = TimestampQualification.TSA;
			}
		}

	}

	@Override
	protected void addAdditionalInfo() {
		determineFinalQualification();
	}

	private void determineFinalQualification() {
		result.setTimestampQualification(tstQualif);
	}

	private XmlTLAnalysis getTlAnalysis(String url) {
		for (XmlTLAnalysis xmlTLAnalysis : tlAnalysis) {
			if (Utils.areStringsEqual(url, xmlTLAnalysis.getURL())) {
				return xmlTLAnalysis;
			}
		}
		return null;
	}

	private ChainItem<XmlValidationTimestampQualification> certificatePathTrusted(CertificateWrapper signingCertificate) {
		return new CertificatePathTrustedCheck<>(i18nProvider, result, signingCertificate, getFailLevelConstraint());
	}

	private AcceptableTrustedListCheck<XmlValidationTimestampQualification> isAcceptableTL(XmlTLAnalysis xmlTLAnalysis) {
		return new AcceptableTrustedListCheck<>(i18nProvider, result, xmlTLAnalysis, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationTimestampQualification> hasQTST(List<TrustedServiceWrapper> services) {
		return new QTSTCheck(i18nProvider, result, services, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationTimestampQualification> hasGrantedStatus(List<TrustedServiceWrapper> services) {
		return new GrantedStatusCheck<>(i18nProvider, result, services, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationTimestampQualification> hasGrantedStatusAtDate(List<TrustedServiceWrapper> services) {
		return new GrantedStatusAtProductionTimeCheck(i18nProvider, result, services, getFailLevelConstraint());
	}

}
