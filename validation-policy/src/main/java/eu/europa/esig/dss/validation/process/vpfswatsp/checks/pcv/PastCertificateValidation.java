package eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlPCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlVTS;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.SubContext;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateSignatureValidCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv.checks.ProspectiveCertificateChainCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv.checks.ValidationTimeSlidingCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.ValidationTimeSliding;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.TokenProxy;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class PastCertificateValidation extends Chain<XmlPCV> {

	private final TokenProxy token;
	private final DiagnosticData diagnosticData;
	private final XmlBasicBuildingBlocks bbb;
	private final POEExtraction poe;

	private final Date currentTime;
	private final ValidationPolicy policy;
	private final Context context;
	private Date controlTime;

	public PastCertificateValidation(TokenProxy token, DiagnosticData diagnosticData, XmlBasicBuildingBlocks bbb, POEExtraction poe, Date currentTime,
			ValidationPolicy policy, Context context) {
		super(new XmlPCV());

		this.token = token;
		this.diagnosticData = diagnosticData;
		this.bbb = bbb;
		this.poe = poe;
		this.currentTime = currentTime;

		this.policy = policy;
		this.context = context;
	}

	@Override
	protected void initChain() {

		String signingCertificateId = token.getSigningCertificateId();

		/*
		 * 9.2.1.4 Processing The following steps shall be performed: 1) Build a
		 * new prospective certificate chain that has not yet been evaluated.
		 * The chain shall satisfy the conditions of a prospective certificate
		 * chain as stated in [4], clause 6.1, using one of the trust anchors
		 * provided in the inputs: a) If no new chain can be built, abort the
		 * processing with the current status and the last chain built or, if no
		 * chain was built, with INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND. b)
		 * Otherwise, go to the next step.
		 */
		ChainItem<XmlPCV> item = firstItem = prospectiveCertificateChain();

		/*
		 * 2) The building block shall run the Certification Path Validation of
		 * IETF RFC 5280 [1], clause 6.1, with the following inputs: the
		 * prospective chain built in the previous step, the trust anchor used
		 * in the previous step, the X.509 parameters provided in the inputs and
		 * a date from the intersection of the validity intervals of all the
		 * certificates in the prospective chain. The validation shall not
		 * include revocation checking for the signing certificate: a) If the
		 * certificate path validation returns PASSED, the building block shall
		 * go to the next step. b) If the certificate path validation returns a
		 * failure indication because an intermediate CA has been determined to
		 * be revoked, the building block shall set the current status to
		 * INDETERMINATE/REVOKED_CA_NO_POE and shall go to step 1. c) If the
		 * certificate path validation returns a failure indication with any
		 * other reason, the building block shall set the current status to
		 * INDETERMINATE/CERTIFICATE_CHAIN_GENERAL_FAILURE and shall go to step
		 * 1. Or d) If the certificate path validation returns any other failure
		 * indication, the building block shall go to step 1.
		 * 
		 * ==> Simplified because DSS only uses one certificate chain
		 */

		Date intervalNotBefore = null;
		Date intervalNotAfter = null;

		List<XmlChainItem> certificateChain = token.getCertificateChain();
		for (XmlChainItem certChainItem : certificateChain) {
			CertificateWrapper certificate = diagnosticData.getUsedCertificateById(certChainItem.getId());
			if (certificate.isTrusted()) {
				// There is not need to check for the trusted certificate
				continue;
			}

			SubContext subContext = SubContext.CA_CERTIFICATE;
			if (Utils.areStringsEqual(signingCertificateId, certChainItem.getId())) {
				subContext = SubContext.SIGNING_CERT;
			}

			if (intervalNotBefore == null || intervalNotBefore.before(certificate.getNotBefore())) {
				intervalNotBefore = certificate.getNotBefore();
			}
			if (intervalNotAfter == null || intervalNotAfter.after(certificate.getNotAfter())) {
				intervalNotAfter = certificate.getNotAfter();
			}

			if (SubContext.CA_CERTIFICATE.equals(subContext) && certificate.isRevoked()) {
				Date caRevocationDate = certificate.getLatestRevocationData().getRevocationDate();
				if (caRevocationDate != null && intervalNotAfter.after(caRevocationDate)) {
					intervalNotAfter = caRevocationDate;
				}

				// TODO REVOKED_CA_NO_POE
			}

			item = item.setNextItem(certificateSignatureValid(certificate, subContext));
		}

		/*
		 * 3) The building block shall perform the validation time sliding
		 * process as per clause 5.6.2.2 with the following inputs: the
		 * prospective chain, the set of POEs and the cryptographic constraints.
		 * If it outputs a success indication, the building block shall go to
		 * the next step. Otherwise, the building block shall set the current
		 * status to the returned indication and sub-indication and shall go
		 * back to step 1.
		 */
		item = item.setNextItem(validationTimeSliding());

		/*
		 * 4) The building block shall apply the chain constraints to the chain.
		 * If the chain does not match these constraints, the building block
		 * shall set the current status to FAILED/CHAIN_CONSTRAINTS_FAILURE and
		 * shall go to step 1.
		 */
		if (controlTime != null) {
			certificateChain = token.getCertificateChain();
			for (XmlChainItem certChainItem : certificateChain) {
				CertificateWrapper certificate = diagnosticData.getUsedCertificateById(certChainItem.getId());
				if (certificate.isTrusted()) {
					// There is not need to check for the trusted certificate
					continue;
				}

				SubContext subContext = SubContext.CA_CERTIFICATE;
				if (Utils.areStringsEqual(signingCertificateId, certChainItem.getId())) {
					subContext = SubContext.SIGNING_CERT;
				}

				item = item.setNextItem(cryptographicCheck(result, certificate, controlTime, subContext));
			}

		}

		/*
		 * 5) The building block shall return the current status . If the
		 * current status is PASSED, the building block shall also return the
		 * certificate chain as well as the calculated validation time returned
		 * in step 3.
		 */
	}

	private ChainItem<XmlPCV> prospectiveCertificateChain() {
		LevelConstraint constraint = policy.getProspectiveCertificateChainConstraint(context);
		return new ProspectiveCertificateChainCheck(result, token, diagnosticData, constraint);
	}

	private ChainItem<XmlPCV> certificateSignatureValid(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = policy.getCertificateSignatureConstraint(context, subContext);
		return new CertificateSignatureValidCheck<XmlPCV>(result, certificate, constraint);
	}

	private ChainItem<XmlPCV> validationTimeSliding() {
		ValidationTimeSliding validationTimeSliding = new ValidationTimeSliding(diagnosticData, token, currentTime, context, poe, policy);
		XmlVTS vts = validationTimeSliding.execute();
		bbb.setVTS(vts);
		controlTime = vts.getControlTime();

		return new ValidationTimeSlidingCheck(result, vts, getFailLevelConstraint());
	}

	private ChainItem<XmlPCV> cryptographicCheck(XmlPCV result, CertificateWrapper certificate, Date validationTime, SubContext subContext) {
		CryptographicConstraint constraint = policy.getCertificateCryptographicConstraint(context, subContext);
		return new CryptographicCheck<XmlPCV>(result, certificate, validationTime, constraint);
	}

	@Override
	protected void addAdditionalInfo() {
		result.setControlTime(controlTime); // can be null
	}

}
