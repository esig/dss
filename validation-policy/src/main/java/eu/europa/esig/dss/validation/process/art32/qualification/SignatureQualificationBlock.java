package eu.europa.esig.dss.validation.process.art32.qualification;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSignatureAnalysis;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.CertificatePathTrustedCheck;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.QualifiedCertificateAtCertificateIssuanceCheck;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.QualifiedCertificateAtSigningTimeCheck;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.ServiceConsistencyCheck;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.filter.TrustedServiceFilter;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.filter.TrustedServicesFilterFactory;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class SignatureQualificationBlock extends Chain<XmlSignatureAnalysis> {

	private final SignatureWrapper signature;
	private final DiagnosticData diagnosticData;
	private final ValidationPolicy policy;

	public SignatureQualificationBlock(SignatureWrapper signature, DiagnosticData diagnosticData, ValidationPolicy policy) {
		super(new XmlSignatureAnalysis());

		result.setId(signature.getId());

		this.signature = signature;
		this.diagnosticData = diagnosticData;
		this.policy = policy;
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

			// Art32 :
			// (a) the certificate that supports the signature was, at the time of signing, a qualified certificate for
			// electronic signature complying with Annex I;

			item = item.setNextItem(qualifiedCertificateAtSigningTime(signingCertificate, signature.getDateTime(), servicesForESign));

			// (b) the qualified certificate
			// 1. was issued by a qualified trust service provider
			item = item.setNextItem(qualifiedCertificateAtIssuance(signingCertificate, servicesForESign));

			// TODO

			// (f) the electronic signature was created by a qualified electronic signature creation device;
			item = item.setNextItem(sscdAtSigningTime(signingCertificate, signature.getDateTime(), servicesForESign));

		}

	}

	private ChainItem<XmlSignatureAnalysis> certificatePathTrusted(CertificateWrapper signingCertificate) {
		return new CertificatePathTrustedCheck(result, signingCertificate, getFailLevelConstraint());
	}

	private ChainItem<XmlSignatureAnalysis> servicesConsistency(List<TrustedServiceWrapper> servicesForESign) {
		return new ServiceConsistencyCheck(result, servicesForESign, getWarnLevelConstraint());
	}

	private ChainItem<XmlSignatureAnalysis> qualifiedCertificateAtSigningTime(CertificateWrapper signingCertificate, Date signingTime,
			List<TrustedServiceWrapper> servicesForESign) {
		return new QualifiedCertificateAtSigningTimeCheck(result, signingCertificate, signingTime, servicesForESign, getWarnLevelConstraint());
	}

	private ChainItem<XmlSignatureAnalysis> qualifiedCertificateAtIssuance(CertificateWrapper signingCertificate,
			List<TrustedServiceWrapper> servicesForESign) {
		return new QualifiedCertificateAtCertificateIssuanceCheck(result, signingCertificate, servicesForESign, getWarnLevelConstraint());
	}

	private ChainItem<XmlSignatureAnalysis> sscdAtSigningTime(CertificateWrapper signingCertificate, Date signingTime,
			List<TrustedServiceWrapper> servicesForESign) {
		return new SSCDCertificateAtSigningTime(result, signingCertificate, signingTime, servicesForESign);
	}

}
