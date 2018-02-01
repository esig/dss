package eu.europa.esig.dss.validation.process.qualification.signature;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlTLAnalysis;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationCertificateQualification;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationSignatureQualification;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateQualification;
import eu.europa.esig.dss.validation.SignatureQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.QualificationTime;
import eu.europa.esig.dss.validation.process.qualification.certificate.CertQualificationAtTimeBlock;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.AcceptableTrustedListCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.AdESAcceptableCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.CertificatePathTrustedCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.ForeSignatureAtSigningTimeCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.QSCDCertificateAtSigningTimeCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.QualifiedCertificateAtCertificateIssuanceCheck;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.QualifiedCertificateAtSigningTimeCheck;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedServiceFilter;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedServicesFilterFactory;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class SignatureQualificationBlock extends Chain<XmlValidationSignatureQualification> {

	private final XmlConclusion etsi319102Conclusion;
	private final Date signingTime; // TODO bestSigningTime ?
	private final CertificateWrapper signingCertificate;
	private final List<XmlTLAnalysis> tlAnalysis;
	private final String lotlCountryCode;

	private CertificateQualification qualificationAtSigningTime;

	public SignatureQualificationBlock(XmlConclusion etsi319102Conclusion, Date signingTime, CertificateWrapper signingCertificate,
			List<XmlTLAnalysis> tlAnalysis, String lotlCountryCode) {
		super(new XmlValidationSignatureQualification());

		// result.setId(signature.getId()); TODO

		this.etsi319102Conclusion = etsi319102Conclusion;
		this.signingTime = signingTime;
		this.signingCertificate = signingCertificate;
		this.tlAnalysis = tlAnalysis;
		this.lotlCountryCode = lotlCountryCode;
	}

	@Override
	protected void initChain() {

		ChainItem<XmlValidationSignatureQualification> item = firstItem = isAdES(etsi319102Conclusion);

		item = item.setNextItem(certificatePathTrusted(signingCertificate));

		if (signingCertificate != null && signingCertificate.hasTrustedServices()) {

			XmlTLAnalysis lotlAnalysis = getTlAnalysis(lotlCountryCode);
			if (lotlAnalysis != null) {
				item = item.setNextItem(isAcceptableTL(lotlAnalysis));
			}

			List<TrustedServiceWrapper> originalTSPs = signingCertificate.getTrustedServices();

			// 1. filter by service for CAQC
			TrustedServiceFilter filter = TrustedServicesFilterFactory.createFilterForAcceptableCAQC();
			List<TrustedServiceWrapper> caqcServices = filter.filter(originalTSPs);

			Set<String> caQcCountryCodes = getCountryCodes(caqcServices);
			for (String countryCode : caQcCountryCodes) {
				XmlTLAnalysis currentTL = getTlAnalysis(countryCode);
				if (currentTL != null) {
					item = item.setNextItem(isAcceptableTL(currentTL));
				}
			}

			CertQualificationAtTimeBlock certQualAtIssuanceBlock = new CertQualificationAtTimeBlock(QualificationTime.CERTIFICATE_ISSUANCE_TIME,
					signingCertificate, caqcServices);
			XmlValidationCertificateQualification certQualAtIssuanceResult = certQualAtIssuanceBlock.execute();
			result.getValidationCertificateQualification().add(certQualAtIssuanceResult);
			CertificateQualification qualificationAtIssuance = certQualAtIssuanceResult.getCertificateQualification();

			CertQualificationAtTimeBlock certQualAtSigningTimeBlock = new CertQualificationAtTimeBlock(QualificationTime.SIGNING_TIME, signingTime,
					signingCertificate, caqcServices);
			XmlValidationCertificateQualification certQualAtSigningTimeResult = certQualAtSigningTimeBlock.execute();
			result.getValidationCertificateQualification().add(certQualAtSigningTimeResult);
			qualificationAtSigningTime = certQualAtSigningTimeResult.getCertificateQualification();

			// Article 32 :
			// (a) the certificate that supports the signature was, at the time of signing, a qualified certificate for
			// electronic signature complying with Annex I;
			item = item.setNextItem(qualifiedCertificateAtSigningTime(qualificationAtSigningTime));

			item = item.setNextItem(foreSignatureAtSigningTime(qualificationAtSigningTime));

			// (b) the qualified certificate
			// 1. was issued by a qualified trust service provider
			item = item.setNextItem(qualifiedCertificateAtIssuance(qualificationAtIssuance));

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

		determineFinalQualification();
	}

	private void determineFinalQualification() {
		SignatureQualification sigQualif = SignatureQualification.NA;

		if (etsi319102Conclusion != null && qualificationAtSigningTime != null) {
			sigQualif = SigQualificationMatrix.getSignatureQualification(etsi319102Conclusion.getIndication(), qualificationAtSigningTime);
		}

		result.setSignatureQualification(sigQualif);
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

	private ChainItem<XmlValidationSignatureQualification> certificatePathTrusted(CertificateWrapper signingCertificate) {
		return new CertificatePathTrustedCheck(result, signingCertificate, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationSignatureQualification> isAcceptableTL(XmlTLAnalysis xmlTLAnalysis) {
		return new AcceptableTrustedListCheck<XmlValidationSignatureQualification>(result, xmlTLAnalysis, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationSignatureQualification> isAdES(XmlConclusion etsi319102Conclusion) {
		return new AdESAcceptableCheck(result, etsi319102Conclusion, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationSignatureQualification> qualifiedCertificateAtSigningTime(CertificateQualification qualificationAtSigningTime) {
		return new QualifiedCertificateAtSigningTimeCheck(result, qualificationAtSigningTime, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationSignatureQualification> foreSignatureAtSigningTime(CertificateQualification qualificationAtSigningTime) {
		return new ForeSignatureAtSigningTimeCheck(result, qualificationAtSigningTime, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationSignatureQualification> qualifiedCertificateAtIssuance(CertificateQualification qualificationAtIssuance) {
		return new QualifiedCertificateAtCertificateIssuanceCheck(result, qualificationAtIssuance, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationSignatureQualification> qscdAtSigningTime(CertificateQualification qualificationAtSigningTime) {
		return new QSCDCertificateAtSigningTimeCheck(result, qualificationAtSigningTime, getWarnLevelConstraint());
	}

}
