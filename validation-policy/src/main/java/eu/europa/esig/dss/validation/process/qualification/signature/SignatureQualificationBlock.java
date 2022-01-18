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
package eu.europa.esig.dss.validation.process.qualification.signature;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusionWithProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationSignatureQualification;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.CertificateQualifiedStatus;
import eu.europa.esig.dss.enumerations.CertificateType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.QSCDStatus;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.certificate.CertQualificationAtTimeBlock;
import eu.europa.esig.dss.validation.process.qualification.certificate.CertQualificationMatrix;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.AcceptableListOfTrustedListsCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.AcceptableTrustedListCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.AcceptableTrustedListPresenceCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.AdESAcceptableCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.CertificateTypeAtSigningTimeCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.QSCDCertificateAtSigningTimeCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.QualifiedCertificateAtCertificateIssuanceCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.QualifiedCertificateAtSigningTimeCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.TrustedListReachedForCertificateChainCheck;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedServiceFilter;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedServicesFilterFactory;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Performs the qualification verification for a signature
 */
public class SignatureQualificationBlock extends Chain<XmlValidationSignatureQualification> {

	/** The conclusion of signature validation as in EN 319 102-1 */
	private final XmlConclusion etsi319102Conclusion;

	/** The best-signature-time */
	private final Date bestSignatureTime;

	/** The signing certificate */
	private final CertificateWrapper signingCertificate;

	/** The analyses of all available LOTL/TLs */
	private final List<XmlTLAnalysis> tlAnalysis;

	/** The list of related LOTL/TL analyses */
	private final List<XmlTLAnalysis> relatedTLAnalyses = new ArrayList<>();

	/** The determined signing certificate qualification at its issuance time */
	private CertificateQualification qualificationAtIssuanceTime;

	/** The determined signing certificate qualification at best-signature-time */
	private CertificateQualification qualificationAtSigningTime;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider
	 *  				{@link I18nProvider}
	 * @param etsi319102validation {@link XmlConstraintsConclusionWithProofOfExistence}
	 *  				result of signature validation process as in EN 319 102-1
	 * @param signingCertificate
	 *  				{@link CertificateWrapper} signing certificate used to create the signature
	 * @param tlAnalysis
	 *  				a list of performed {@link XmlTLAnalysis}
	 */
	public SignatureQualificationBlock(I18nProvider i18nProvider,
									   XmlConstraintsConclusionWithProofOfExistence etsi319102validation,
									   CertificateWrapper signingCertificate, List<XmlTLAnalysis> tlAnalysis) {
		super(i18nProvider, new XmlValidationSignatureQualification());

		this.etsi319102Conclusion = etsi319102validation.getConclusion();
		this.bestSignatureTime = etsi319102validation.getProofOfExistence().getTime();
		this.signingCertificate = signingCertificate;
		this.tlAnalysis = tlAnalysis;
	}
	
	@Override
	protected MessageTag getTitle() {
		return MessageTag.SIG_QUALIFICATION;
	}

	@Override
	protected void initChain() {

		ChainItem<XmlValidationSignatureQualification> item = firstItem = isAdES(etsi319102Conclusion);

		item = item.setNextItem(isTrustedListReachedForCertificateChain(signingCertificate));

		if (signingCertificate != null && signingCertificate.isTrustedListReached()) {

			List<TrustedServiceWrapper> originalTSPs = signingCertificate.getTrustedServices();
			
			Set<String> listOfTrustedListUrls = originalTSPs.stream().filter(t -> t.getListOfTrustedLists() != null)
					.map(t -> t.getListOfTrustedLists().getUrl()).collect(Collectors.toSet());

			Set<String> acceptableLOTLUrls = new HashSet<>();
			for (String lotlURL : listOfTrustedListUrls) {
				XmlTLAnalysis lotlAnalysis = getTlAnalysis(lotlURL);
				if (lotlAnalysis != null) {
					relatedTLAnalyses.add(lotlAnalysis);

					AcceptableListOfTrustedListsCheck<XmlValidationSignatureQualification> acceptableLOTL = isAcceptableLOTL(lotlAnalysis);
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

						AcceptableTrustedListCheck<XmlValidationSignatureQualification> acceptableTL = isAcceptableTL(currentTL);
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
				TrustedServiceFilter filter = TrustedServicesFilterFactory.createFilterByUrls(acceptableTLUrls);
				List<TrustedServiceWrapper> acceptableServices = filter.filter(originalTSPs);
	
				filter = TrustedServicesFilterFactory.createFilterByCaQc();
				List<TrustedServiceWrapper> caqcServices = filter.filter(acceptableServices);
	
				CertQualificationAtTimeBlock certQualAtIssuanceBlock = new CertQualificationAtTimeBlock(i18nProvider, ValidationTime.CERTIFICATE_ISSUANCE_TIME,
						signingCertificate, caqcServices);
				XmlValidationCertificateQualification certQualAtIssuanceResult = certQualAtIssuanceBlock.execute();
				result.getValidationCertificateQualification().add(certQualAtIssuanceResult);
				qualificationAtIssuanceTime = certQualAtIssuanceResult.getCertificateQualification();
	
				CertQualificationAtTimeBlock certQualAtSigningTimeBlock = new CertQualificationAtTimeBlock(i18nProvider, ValidationTime.BEST_SIGNATURE_TIME, bestSignatureTime,
						signingCertificate, caqcServices);
				XmlValidationCertificateQualification certQualAtSigningTimeResult = certQualAtSigningTimeBlock.execute();
				result.getValidationCertificateQualification().add(certQualAtSigningTimeResult);
				qualificationAtSigningTime = certQualAtSigningTimeResult.getCertificateQualification();
	
				// Article 32 :
				// (a) the certificate that supports the signature was, at the time of signing, a qualified certificate for
				// electronic signature complying with Annex I;
				item = item.setNextItem(qualifiedCertificateAtSigningTime(qualificationAtSigningTime));

				// NOTE: Article 40:
				// Articles 32, 33 and 34 shall apply mutatis mutandis to the validation and preservation of
				// qualified electronic seals.
				item = item.setNextItem(certificateTypeAtSigningTime(qualificationAtSigningTime));
	
				// (b) the qualified certificate
				// 1. was issued by a qualified trust service provider
				item = item.setNextItem(qualifiedCertificateAtIssuance(qualificationAtIssuanceTime));
	
				// 2. was valid at the time of signing;
				// covered in isAdES
	
				// (c) the signature validation data corresponds to the data provided to the relying party;
				// covered in isAdES
	
				// (d) the unique set of data representing the signatory in the certificate is correctly provided to the
				// relying party;
				// covered in isAdES
	
				// (e) the use of any pseudonym is clearly indicated to the relying party if a pseudonym was used at the
				// time of signing;
				// covered in isAdES
	
				// (f) the electronic signature was created by a qualified electronic signature creation device;
				item = item.setNextItem(qscdAtSigningTime(qualificationAtSigningTime));
	
				// (g) the integrity of the signed data has not been compromised;
				// covered in isAdES
				
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

	@Override
	protected void addAdditionalInfo() {
		setIndication();
		determineFinalQualification();
	}

	@Override
	protected void collectAdditionalMessages(XmlConclusion conclusion) {
		for (XmlValidationCertificateQualification certQualAtTime : result.getValidationCertificateQualification()) {
			collectAllMessages(conclusion, certQualAtTime.getConclusion());
		}
		for (XmlTLAnalysis tlAnalysis : relatedTLAnalyses) {
			collectAllMessages(conclusion, tlAnalysis.getConclusion());
		}
	}

	private void determineFinalQualification() {
		SignatureQualification sigQualif = SignatureQualification.NA;

		if (etsi319102Conclusion != null && qualificationAtIssuanceTime != null && qualificationAtSigningTime != null) {
			CertificateQualification finalCertQualification = getFinalCertQualification(qualificationAtIssuanceTime, qualificationAtSigningTime);
			sigQualif = SigQualificationMatrix.getSignatureQualification(etsi319102Conclusion.getIndication(), finalCertQualification);
		}

		result.setSignatureQualification(sigQualif);
	}

	private CertificateQualification getFinalCertQualification(
			CertificateQualification certQualAtIssuanceTime, CertificateQualification certQualAtSigningTime) {
		CertificateQualifiedStatus qualStatus = getFinalCertQualStatus(certQualAtIssuanceTime, certQualAtSigningTime);
		CertificateType type = getFinalCertificateType(certQualAtIssuanceTime, certQualAtSigningTime);
		QSCDStatus qscd = getFinalQSCDStatus(certQualAtSigningTime);
		return CertQualificationMatrix.getCertQualification(qualStatus, type, qscd);
	}

	private CertificateQualifiedStatus getFinalCertQualStatus(
			CertificateQualification certQualAtIssuanceTime, CertificateQualification certQualAtSigningTime) {
		return certQualAtIssuanceTime.isQc() && certQualAtSigningTime.isQc() ?
				CertificateQualifiedStatus.QC : CertificateQualifiedStatus.NOT_QC;
	}

	private CertificateType getFinalCertificateType(
			CertificateQualification certQualAtIssuanceTime, CertificateQualification certQualAtSigningTime) {
		if (certQualAtIssuanceTime.getType() == certQualAtSigningTime.getType()) {
			return certQualAtSigningTime.getType();
		}
		return CertificateType.UNKNOWN;
	}

	private QSCDStatus getFinalQSCDStatus(CertificateQualification certQualAtSigningTime) {
		return certQualAtSigningTime.isQscd() ? QSCDStatus.QSCD : QSCDStatus.NOT_QSCD;
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

	private ChainItem<XmlValidationSignatureQualification> isTrustedListReachedForCertificateChain(CertificateWrapper signingCertificate) {
		return new TrustedListReachedForCertificateChainCheck<>(i18nProvider, result, signingCertificate, getFailLevelConstraint());
	}

	private AcceptableListOfTrustedListsCheck<XmlValidationSignatureQualification> isAcceptableLOTL(XmlTLAnalysis xmlLOTLAnalysis) {
		return new AcceptableListOfTrustedListsCheck<>(i18nProvider, result, xmlLOTLAnalysis, getWarnLevelConstraint());
	}

	private AcceptableTrustedListCheck<XmlValidationSignatureQualification> isAcceptableTL(XmlTLAnalysis xmlTLAnalysis) {
		return new AcceptableTrustedListCheck<>(i18nProvider, result, xmlTLAnalysis, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationSignatureQualification> isAcceptableTLPresent(Set<String> acceptableUrls) {
		return new AcceptableTrustedListPresenceCheck<>(i18nProvider, result, acceptableUrls, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationSignatureQualification> isAdES(XmlConclusion etsi319102Conclusion) {
		return new AdESAcceptableCheck(i18nProvider, result, etsi319102Conclusion, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationSignatureQualification> qualifiedCertificateAtSigningTime(CertificateQualification qualificationAtSigningTime) {
		return new QualifiedCertificateAtSigningTimeCheck(i18nProvider, result, qualificationAtSigningTime, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationSignatureQualification> certificateTypeAtSigningTime(CertificateQualification qualificationAtSigningTime) {
		return new CertificateTypeAtSigningTimeCheck(i18nProvider, result, qualificationAtSigningTime, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationSignatureQualification> qualifiedCertificateAtIssuance(CertificateQualification qualificationAtIssuance) {
		return new QualifiedCertificateAtCertificateIssuanceCheck(i18nProvider, result, qualificationAtIssuance, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationSignatureQualification> qscdAtSigningTime(CertificateQualification qualificationAtSigningTime) {
		return new QSCDCertificateAtSigningTimeCheck(i18nProvider, result, qualificationAtSigningTime, getWarnLevelConstraint());
	}

}
