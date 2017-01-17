package eu.europa.esig.dss.validation.process.art32.qualification;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSignatureAnalysis;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.Condition;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.AdESCheck;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.CertificatePathTrustedCheck;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.QSCDCertificateAtSigningTimeCheck;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.QualifiedCertificateAtCertificateIssuanceCheck;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.QualifiedCertificateAtSigningTimeCheck;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.ServiceConsistencyCheck;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.filter.TrustedServiceFilter;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.filter.TrustedServicesFilterFactory;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class SignatureQualificationBlock extends Chain<XmlSignatureAnalysis> {

	private final XmlConclusion etsi319102Conclusion;
	private final SignatureWrapper signature;
	private final DiagnosticData diagnosticData;

	private QualifiedCertificateAtSigningTimeCheck qualifiedAtSigningTime;
	private QSCDCertificateAtSigningTimeCheck qscdAtSigningTime;

	public SignatureQualificationBlock(XmlConclusion etsi319102Conclusion, SignatureWrapper signature, DiagnosticData diagnosticData) {
		super(new XmlSignatureAnalysis());

		result.setId(signature.getId());

		this.etsi319102Conclusion = etsi319102Conclusion;
		this.signature = signature;
		this.diagnosticData = diagnosticData;
	}

	@Override
	protected void initChain() {

		String signingCertificateId = signature.getSigningCertificateId();
		CertificateWrapper signingCertificate = diagnosticData.getUsedCertificateById(signingCertificateId);

		ChainItem<XmlSignatureAnalysis> item = firstItem = certificatePathTrusted(signingCertificate);

		if (signingCertificate != null) {

			List<TrustedServiceWrapper> originalTSPs = signingCertificate.getTrustedServices();

			// 1. filter by service for esign
			TrustedServiceFilter filter = TrustedServicesFilterFactory.createFilterForEsign();
			List<TrustedServiceWrapper> servicesForESign = filter.filter(originalTSPs);

			// 2. Consistency of trusted services ?
			item = item.setNextItem(servicesConsistency(servicesForESign));

			item = item.setNextItem(isAdES(etsi319102Conclusion));

			// Article 32 :
			// (a) the certificate that supports the signature was, at the time of signing, a qualified certificate for
			// electronic signature complying with Annex I;
			qualifiedAtSigningTime = (QualifiedCertificateAtSigningTimeCheck) qualifiedCertificateAtSigningTime(signingCertificate, signature.getDateTime(),
					servicesForESign);
			item = item.setNextItem(qualifiedAtSigningTime);

			// (b) the qualified certificate
			// 1. was issued by a qualified trust service provider
			item = item.setNextItem(qualifiedCertificateAtIssuance(signingCertificate, servicesForESign));

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
			qscdAtSigningTime = (QSCDCertificateAtSigningTimeCheck) qscdAtSigningTime(signingCertificate, signature.getDateTime(), servicesForESign,
					qualifiedAtSigningTime);
			item = item.setNextItem(qscdAtSigningTime);

			// (g) the integrity of the signed data has not been compromised;
			// covered in isAdES
		}
	}

	@Override
	protected void addAdditionalInfo() {
		determineFinalQualification();
		collectErrorsWarnsInfos();
		setIndication();
	}

	private void determineFinalQualification() {
		SignatureQualification sigQualif = null;
		if (qualifiedAtSigningTime != null && qscdAtSigningTime != null) {
			if (QualifiedStatus.QC_FOR_ESIGN == qualifiedAtSigningTime.getQualifiedStatus()) {
				if (qscdAtSigningTime.check()) {
					sigQualif = SignatureQualification.QESig;
				} else {
					sigQualif = SignatureQualification.AdESig_QC;
				}
			} else {
				sigQualif = SignatureQualification.AdES;
			}
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

	private ChainItem<XmlSignatureAnalysis> certificatePathTrusted(CertificateWrapper signingCertificate) {
		return new CertificatePathTrustedCheck(result, signingCertificate, getFailLevelConstraint());
	}

	private ChainItem<XmlSignatureAnalysis> servicesConsistency(List<TrustedServiceWrapper> servicesForESign) {
		return new ServiceConsistencyCheck(result, servicesForESign, getWarnLevelConstraint());
	}

	private ChainItem<XmlSignatureAnalysis> isAdES(XmlConclusion etsi319102Conclusion) {
		return new AdESCheck(result, etsi319102Conclusion, getWarnLevelConstraint());
	}

	private ChainItem<XmlSignatureAnalysis> qualifiedCertificateAtSigningTime(CertificateWrapper signingCertificate, Date signingTime,
			List<TrustedServiceWrapper> servicesForESign) {
		return new QualifiedCertificateAtSigningTimeCheck(result, signingCertificate, signingTime, servicesForESign, getWarnLevelConstraint());
	}

	private ChainItem<XmlSignatureAnalysis> qualifiedCertificateAtIssuance(CertificateWrapper signingCertificate,
			List<TrustedServiceWrapper> servicesForESign) {
		return new QualifiedCertificateAtCertificateIssuanceCheck(result, signingCertificate, servicesForESign, getWarnLevelConstraint());
	}

	private ChainItem<XmlSignatureAnalysis> qscdAtSigningTime(CertificateWrapper signingCertificate, Date signingTime,
			List<TrustedServiceWrapper> servicesForESign, Condition qualifiedStatusAtSigningTime) {
		return new QSCDCertificateAtSigningTimeCheck(result, signingCertificate, signingTime, servicesForESign, qualifiedStatusAtSigningTime,
				getWarnLevelConstraint());
	}

}
