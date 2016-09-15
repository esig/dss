package eu.europa.esig.dss.validation.process.bbb.xcv;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.SubContext;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.CheckSubXCVResult;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.ProspectiveCertificateChainCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.TrustedServiceStatusCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.TrustedServiceTypeIdentifierCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.SubX509CertificateValidation;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.jaxb.policy.LevelConstraint;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

/**
 * 5.2.6 X.509 certificate validation This building block validates the signing
 * certificate at current time.
 */
public class X509CertificateValidation extends Chain<XmlXCV> {

	private final DiagnosticData diagnosticData;
	private final CertificateWrapper currentCertificate;
	private final Date currentTime;
	private final Date usageTime;

	private final Context context;
	private final ValidationPolicy validationPolicy;

	public X509CertificateValidation(DiagnosticData diagnosticData, CertificateWrapper currentCertificate, Date currentTime, Date usageTime, Context context,
			ValidationPolicy validationPolicy) {
		super(new XmlXCV());

		this.diagnosticData = diagnosticData;
		this.currentCertificate = currentCertificate;
		this.currentTime = currentTime;
		this.usageTime = usageTime;

		this.context = context;
		this.validationPolicy = validationPolicy;
	}

	@Override
	protected void initChain() {

		ChainItem<XmlXCV> item = firstItem = prospectiveCertificateChain();

		item = item.setNextItem(trustedServiceWithExpectedTypeIdentifier());

		item = item.setNextItem(trustedServiceWithExpectedStatus());

		SubX509CertificateValidation certificateValidation = new SubX509CertificateValidation(currentCertificate, currentTime, context, SubContext.SIGNING_CERT,
				validationPolicy);
		XmlSubXCV subXCV = certificateValidation.execute();
		result.getSubXCV().add(subXCV);

		// Check CA_CERTIFICATEs
		List<XmlChainItem> certificateChainList = currentCertificate.getCertificateChain();
		if (Utils.isCollectionNotEmpty(certificateChainList)) {
			for (XmlChainItem chainCertificate : certificateChainList) {
				CertificateWrapper certificate = diagnosticData.getUsedCertificateByIdNullSafe(chainCertificate.getId());

				certificateValidation = new SubX509CertificateValidation(certificate, currentTime, context, SubContext.CA_CERTIFICATE, validationPolicy);
				subXCV = certificateValidation.execute();
				result.getSubXCV().add(subXCV);
			}
		}

		for (XmlSubXCV subXCVresult : result.getSubXCV()) {
			item = item.setNextItem(checkSubXCVResult(subXCVresult));
		}

	}

	private ChainItem<XmlXCV> prospectiveCertificateChain() {
		LevelConstraint constraint = validationPolicy.getProspectiveCertificateChainConstraint(context);
		return new ProspectiveCertificateChainCheck(result, currentCertificate, diagnosticData, context, constraint);
	}

	private ChainItem<XmlXCV> trustedServiceWithExpectedTypeIdentifier() {
		MultiValuesConstraint constraint = validationPolicy.getTrustedServiceTypeIdentifierConstraint(context);
		return new TrustedServiceTypeIdentifierCheck(result, currentCertificate, usageTime, context, constraint);
	}

	private ChainItem<XmlXCV> trustedServiceWithExpectedStatus() {
		MultiValuesConstraint constraint = validationPolicy.getTrustedServiceStatusConstraint(context);
		return new TrustedServiceStatusCheck(result, currentCertificate, usageTime, context, constraint);
	}

	private ChainItem<XmlXCV> checkSubXCVResult(XmlSubXCV subXCVresult) {
		return new CheckSubXCVResult(result, subXCVresult, getFailLevelConstraint());
	}

}
