package eu.europa.esig.dss.validation.process.qmatrix.qualification;

import java.util.Date;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSignatureAnalysis;
import eu.europa.esig.dss.jaxb.detailedreport.XmlTLAnalysis;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureQualification;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.Condition;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.AcceptableTrustedListCheck;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.AdESAcceptableCheck;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.CertificateAndServiceConsistencyCheck;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.CertificatePathTrustedCheck;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.ForeSignatureAtSigningTimeCheck;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.QSCDCertificateAtSigningTimeCheck;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.QualifiedCertificateAtCertificateIssuanceCheck;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.QualifiedCertificateAtSigningTimeCheck;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.ServiceConsistencyCheck;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.filter.TrustedServiceFilter;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.filter.TrustedServicesFilterFactory;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.Type;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class SignatureQualificationBlock extends Chain<XmlSignatureAnalysis> {

	private final XmlConclusion etsi319102Conclusion;
	private final List<XmlTLAnalysis> tlAnalysis;
	private final SignatureWrapper signature;
	private final DiagnosticData diagnosticData;
	private final ValidationPolicy policy;

	private QualifiedCertificateAtSigningTimeCheck qualifiedAtSigningTime;
	private ForeSignatureAtSigningTimeCheck foreSignatureAtSigningTime;
	private QSCDCertificateAtSigningTimeCheck qscdAtSigningTime;

	public SignatureQualificationBlock(XmlConclusion etsi319102Conclusion, List<XmlTLAnalysis> tlAnalysis, SignatureWrapper signature,
			DiagnosticData diagnosticData, ValidationPolicy policy) {
		super(new XmlSignatureAnalysis());

		result.setId(signature.getId());

		this.etsi319102Conclusion = etsi319102Conclusion;
		this.tlAnalysis = tlAnalysis;
		this.signature = signature;
		this.diagnosticData = diagnosticData;
		this.policy = policy;
	}

	@Override
	protected void initChain() {

		String signingCertificateId = signature.getSigningCertificateId();
		CertificateWrapper signingCertificate = diagnosticData.getUsedCertificateById(signingCertificateId);

		ChainItem<XmlSignatureAnalysis> item = firstItem = isAdES(etsi319102Conclusion);

		item = item.setNextItem(certificatePathTrusted(signingCertificate));

		if (signingCertificate != null && signingCertificate.hasTrustedServices()) {

			XmlTLAnalysis lotlAnalysis = getTLAnalysis(diagnosticData.getLOTLCountryCode());
			if (lotlAnalysis != null) {
				item = item.setNextItem(isAcceptableTL(lotlAnalysis));
			}

			Set<String> trustedListCountryCodes = signingCertificate.getTrustedListCountryCodes();
			for (String countryCode : trustedListCountryCodes) {
				XmlTLAnalysis currentTL = getTLAnalysis(countryCode);
				if (currentTL != null) {
					item = item.setNextItem(isAcceptableTL(currentTL));
				}
			}

			List<TrustedServiceWrapper> originalTSPs = signingCertificate.getTrustedServices();

			// 1. filter by service for CAQC
			TrustedServiceFilter filter = TrustedServicesFilterFactory.createFilterForAcceptableCAQC();
			List<TrustedServiceWrapper> caqcServices = filter.filter(originalTSPs);

			// 2. Consistency of trust services ?
			item = item.setNextItem(servicesConsistency(caqcServices));

			item = item.setNextItem(serviceAndCertificateConsistency(caqcServices, signingCertificate));

			Date bestSigningTime = signature.getDateTime(); // TODO

			// Article 32 :
			// (a) the certificate that supports the signature was, at the time of signing, a qualified certificate for
			// electronic signature complying with Annex I;
			qualifiedAtSigningTime = (QualifiedCertificateAtSigningTimeCheck) qualifiedCertificateAtSigningTime(signingCertificate, bestSigningTime,
					caqcServices);
			item = item.setNextItem(qualifiedAtSigningTime);

			foreSignatureAtSigningTime = (ForeSignatureAtSigningTimeCheck) foreSignatureAtSigningTime(signingCertificate, bestSigningTime, caqcServices);
			item = item.setNextItem(foreSignatureAtSigningTime);

			// (b) the qualified certificate
			// 1. was issued by a qualified trust service provider
			item = item.setNextItem(qualifiedCertificateAtIssuance(signingCertificate, caqcServices));

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
			qscdAtSigningTime = (QSCDCertificateAtSigningTimeCheck) qscdAtSigningTime(signingCertificate, bestSigningTime, caqcServices,
					qualifiedAtSigningTime);
			item = item.setNextItem(qscdAtSigningTime);

			// (g) the integrity of the signed data has not been compromised;
			// covered in isAdES
		}
	}

	private XmlTLAnalysis getTLAnalysis(String countryCode) {
		for (XmlTLAnalysis xmlTLAnalysis : tlAnalysis) {
			if (Utils.areStringsEqual(countryCode, xmlTLAnalysis.getCountryCode())) {
				return xmlTLAnalysis;
			}
		}
		return null;
	}

	@Override
	protected void addAdditionalInfo() {
		collectErrorsWarnsInfos();
		setIndication();

		determineFinalQualification();
	}

	private void determineFinalQualification() {
		SignatureQualification sigQualif = SignatureQualification.NA;

		if (isAcceptableConclusion() && qualifiedAtSigningTime != null && foreSignatureAtSigningTime != null && qscdAtSigningTime != null) {
			QualifiedStatus qualifiedStatus = qualifiedAtSigningTime.getQualifiedStatus();
			boolean qc = QualifiedStatus.isQC(qualifiedStatus);
			Type type = foreSignatureAtSigningTime.getType();
			boolean qscd = qscdAtSigningTime.check();

			sigQualif = QualificationMatrix.getSignatureQualification(etsi319102Conclusion.getIndication(), qc, type, qscd);
		}

		result.setSignatureQualification(sigQualif);
	}

	private boolean isAcceptableConclusion() {
		XmlConclusion conclusion = result.getConclusion();
		return conclusion != null && Indication.FAILED != conclusion.getIndication();
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

	private ChainItem<XmlSignatureAnalysis> certificatePathTrusted(CertificateWrapper signingCertificate) {
		return new CertificatePathTrustedCheck(result, signingCertificate, getFailLevelConstraint());
	}

	private ChainItem<XmlSignatureAnalysis> isAcceptableTL(XmlTLAnalysis xmlTLAnalysis) {
		return new AcceptableTrustedListCheck(result, xmlTLAnalysis, getFailLevelConstraint());
	}

	private ChainItem<XmlSignatureAnalysis> servicesConsistency(List<TrustedServiceWrapper> caqcServices) {
		return new ServiceConsistencyCheck(result, caqcServices, policy.getTLConsistencyConstraint());
	}

	private ChainItem<XmlSignatureAnalysis> serviceAndCertificateConsistency(List<TrustedServiceWrapper> caqcServices, CertificateWrapper signingCertificate) {
		return new CertificateAndServiceConsistencyCheck(result, signingCertificate, caqcServices, getWarnLevelConstraint());
	}

	private ChainItem<XmlSignatureAnalysis> isAdES(XmlConclusion etsi319102Conclusion) {
		return new AdESAcceptableCheck(result, etsi319102Conclusion, getWarnLevelConstraint());
	}

	private ChainItem<XmlSignatureAnalysis> qualifiedCertificateAtSigningTime(CertificateWrapper signingCertificate, Date signingTime,
			List<TrustedServiceWrapper> caqcServices) {
		return new QualifiedCertificateAtSigningTimeCheck(result, signingCertificate, signingTime, caqcServices, getWarnLevelConstraint());
	}

	private ChainItem<XmlSignatureAnalysis> foreSignatureAtSigningTime(CertificateWrapper signingCertificate, Date signingTime,
			List<TrustedServiceWrapper> caqcServices) {
		return new ForeSignatureAtSigningTimeCheck(result, signingCertificate, signingTime, caqcServices, getWarnLevelConstraint());
	}

	private ChainItem<XmlSignatureAnalysis> qualifiedCertificateAtIssuance(CertificateWrapper signingCertificate, List<TrustedServiceWrapper> caqcServices) {
		return new QualifiedCertificateAtCertificateIssuanceCheck(result, signingCertificate, caqcServices, getWarnLevelConstraint());
	}

	private ChainItem<XmlSignatureAnalysis> qscdAtSigningTime(CertificateWrapper signingCertificate, Date signingTime, List<TrustedServiceWrapper> caqcServices,
			Condition qualifiedStatusAtSigningTime) {
		return new QSCDCertificateAtSigningTimeCheck(result, signingCertificate, signingTime, caqcServices, qualifiedStatusAtSigningTime,
				getWarnLevelConstraint());
	}

}
