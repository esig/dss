package eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.pcv;

import java.util.List;

import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.EN319102.bbb.Chain;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.bbb.xcv.checks.CertificateSignatureValidCheck;
import eu.europa.esig.dss.EN319102.bbb.xcv.checks.ProspectiveCertificateChainCheck;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy.SubContext;
import eu.europa.esig.dss.jaxb.detailedreport.XmlPCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainCertificate;
import eu.europa.esig.dss.validation.CertificateWrapper;
import eu.europa.esig.dss.validation.TokenProxy;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class PastCertificateValidation extends Chain<XmlPCV> {

	private final TokenProxy token;
	private final DiagnosticData diagnosticData;

	private final ValidationPolicy policy;
	private final Context context;

	public PastCertificateValidation(TokenProxy token, DiagnosticData diagnosticData, ValidationPolicy policy, Context context) {
		super(new XmlPCV());

		this.token = token;
		this.diagnosticData = diagnosticData;

		this.policy = policy;
		this.context = context;
	}

	@Override
	protected void initChain() {

		String signingCertificateId = token.getSigningCertificateId();

		/*
		 * 9.2.1.4 Processing
		 * The following steps shall be performed:
		 * 1) Build a new prospective certificate chain that has not yet been evaluated. The chain shall satisfy the
		 * conditions of a prospective certificate chain as stated in [4], clause 6.1, using one of the trust anchors
		 * provided in the inputs:
		 * a) If no new chain can be built, abort the processing with the current status and the last chain built or, if
		 * no chain was built, with INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND.
		 * b) Otherwise, go to the next step.
		 */
		ChainItem<XmlPCV> item = firstItem = prospectiveCertificateChain();

		List<XmlChainCertificate> certificateChain = token.getCertificateChain();
		for (XmlChainCertificate certChainItem : certificateChain) {
			CertificateWrapper certificate = diagnosticData.getUsedCertificateById(certChainItem.getId());
			if (certificate.isTrusted()) {
				// There is not need to check for the trusted certificate
				continue;
			}

			SubContext subContext = SubContext.CA_CERTIFICATE;
			if (StringUtils.equals(signingCertificateId, certChainItem.getId())) {
				subContext = SubContext.SIGNING_CERT;
			}

			item.setNextItem(certificateSignatureValid(certificate, subContext));
		}

	}

	private ChainItem<XmlPCV> prospectiveCertificateChain() {
		LevelConstraint constraint = policy.getProspectiveCertificateChainConstraint(context);
		return new ProspectiveCertificateChainCheck<XmlPCV>(result, token, diagnosticData, constraint);
	}

	private ChainItem<XmlPCV> certificateSignatureValid(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = policy.getCertificateSignatureConstraint(context, subContext);
		return new CertificateSignatureValidCheck<XmlPCV>(result, certificate, constraint);
	}

}
