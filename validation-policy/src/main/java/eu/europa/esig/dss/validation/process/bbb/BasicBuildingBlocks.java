package eu.europa.esig.dss.validation.process.bbb;

import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlFC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlName;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlVCI;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.process.bbb.cv.CryptographicVerification;
import eu.europa.esig.dss.validation.process.bbb.fc.FormatChecking;
import eu.europa.esig.dss.validation.process.bbb.isc.IdentificationOfTheSigningCertificate;
import eu.europa.esig.dss.validation.process.bbb.sav.AbstractAcceptanceValidation;
import eu.europa.esig.dss.validation.process.bbb.sav.RevocationAcceptanceValidation;
import eu.europa.esig.dss.validation.process.bbb.sav.SignatureAcceptanceValidation;
import eu.europa.esig.dss.validation.process.bbb.sav.TimestampAcceptanceValidation;
import eu.europa.esig.dss.validation.process.bbb.vci.ValidationContextInitialization;
import eu.europa.esig.dss.validation.process.bbb.xcv.X509CertificateValidation;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TokenProxy;

/**
 * 5.2 Basic building blocks
 */
public class BasicBuildingBlocks {

	private static final Logger logger = LoggerFactory.getLogger(BasicBuildingBlocks.class);

	private final DiagnosticData diagnosticData;
	private final TokenProxy token;
	private final ValidationPolicy policy;
	private final Date currentTime;
	private final Context context;

	public BasicBuildingBlocks(DiagnosticData diagnosticData, TokenProxy token, Date currentTime, ValidationPolicy policy, Context context) {
		this.diagnosticData = diagnosticData;
		this.token = token;
		this.currentTime = currentTime;
		this.policy = policy;
		this.context = context;
	}

	public XmlBasicBuildingBlocks execute() {
		XmlBasicBuildingBlocks result = new XmlBasicBuildingBlocks();
		result.setId(token.getId());
		result.setType(context.name());
		result.setConclusion(new XmlConclusion());

		/**
		 * 5.2.2 Format Checking
		 */
		XmlFC fc = executeFormatChecking();
		if (fc != null) {
			result.setFC(fc);
			updateFinalConclusion(result, fc);
		}

		/**
		 * 5.2.3 Identification of the signing certificate
		 */
		XmlISC isc = executeIdentificationOfTheSigningCertificate();
		if (isc != null) {
			result.setISC(isc);
			updateFinalConclusion(result, isc);
		}

		/**
		 * 5.2.4 Validation context initialization (only for signature)
		 */
		XmlVCI vci = executeValidationContextInitialization();
		if (vci != null) {
			result.setVCI(vci);
			updateFinalConclusion(result, vci);
		}

		/**
		 * 5.2.6 X.509 certificate validation
		 */
		XmlXCV xcv = executeX509CertificateValidation();
		if (xcv != null) {
			result.setXCV(xcv);
			updateFinalConclusion(result, xcv);
		}

		/**
		 * 5.2.7 Cryptographic verification
		 */
		XmlCV cv = executeCryptographicVerification();
		if (cv != null) {
			result.setCV(cv);
			updateFinalConclusion(result, cv);
		}

		/**
		 * 5.2.8 Signature acceptance validation (SAV)
		 */
		XmlSAV sav = executeSignatureAcceptanceValidation();
		if (sav != null) {
			result.setSAV(sav);
			updateFinalConclusion(result, sav);
		}

		if (result.getConclusion().getIndication() == null) {
			result.getConclusion().setIndication(Indication.PASSED);
		}

		return result;
	}

	private void updateFinalConclusion(XmlBasicBuildingBlocks result, XmlConstraintsConclusion constraintsAndConclusion) {
		XmlConclusion finalConclusion = result.getConclusion();

		XmlConclusion currentConclusion = constraintsAndConclusion.getConclusion();
		List<XmlConstraint> constraints = constraintsAndConclusion.getConstraint();

		if (!Indication.PASSED.equals(currentConclusion.getIndication())) {
			finalConclusion.setIndication(currentConclusion.getIndication());
			finalConclusion.setSubIndication(currentConclusion.getSubIndication());
			finalConclusion.getErrors().addAll(currentConclusion.getErrors());
		}

		if (Utils.isCollectionNotEmpty(constraints)) {
			for (XmlConstraint constraint : constraints) {
				XmlName info = constraint.getInfo();
				if (info != null) {
					finalConclusion.getInfos().add(info);
				}
				XmlName warning = constraint.getWarning();
				if (warning != null) {
					finalConclusion.getWarnings().add(warning);
				}
			}
		}
	}

	private XmlFC executeFormatChecking() {
		if (Context.SIGNATURE.equals(context)) {
			FormatChecking fc = new FormatChecking(diagnosticData, (SignatureWrapper) token, context, policy);
			return fc.execute();
		} else {
			return null;
		}
	}

	private XmlISC executeIdentificationOfTheSigningCertificate() {
		IdentificationOfTheSigningCertificate isc = new IdentificationOfTheSigningCertificate(diagnosticData, token, context, policy);
		return isc.execute();
	}

	private XmlVCI executeValidationContextInitialization() {
		if (Context.SIGNATURE.equals(context)) {
			ValidationContextInitialization vci = new ValidationContextInitialization((SignatureWrapper) token, context, policy);
			return vci.execute();
		}
		return null;
	}

	private XmlCV executeCryptographicVerification() {
		CryptographicVerification cv = new CryptographicVerification(diagnosticData, token, context, policy);
		return cv.execute();
	}

	private XmlXCV executeX509CertificateValidation() {
		CertificateWrapper certificate = diagnosticData.getUsedCertificateById(token.getSigningCertificateId());
		if (certificate != null) {
			if (Context.SIGNATURE.equals(context) || Context.COUNTER_SIGNATURE.equals(context)) {
				X509CertificateValidation xcv = new X509CertificateValidation(diagnosticData, certificate, currentTime, certificate.getNotBefore(), context,
						policy);
				return xcv.execute();
			} else if (Context.TIMESTAMP.equals(context)) {
				X509CertificateValidation xcv = new X509CertificateValidation(diagnosticData, certificate, currentTime,
						((TimestampWrapper) token).getProductionTime(), context, policy);
				return xcv.execute();
			} else if (Context.REVOCATION.equals(context)) {
				X509CertificateValidation xcv = new X509CertificateValidation(diagnosticData, certificate, currentTime,
						((RevocationWrapper) token).getProductionDate(), context, policy);
				return xcv.execute();
			} else {
				logger.info("Unsupported context " + context);
			}
		}
		return null;
	}

	private XmlSAV executeSignatureAcceptanceValidation() {
		AbstractAcceptanceValidation<?> aav = null;
		if (Context.SIGNATURE.equals(context) || Context.COUNTER_SIGNATURE.equals(context)) {
			aav = new SignatureAcceptanceValidation(diagnosticData, currentTime, (SignatureWrapper) token, context, policy);
		} else if (Context.TIMESTAMP.equals(context)) {
			aav = new TimestampAcceptanceValidation(diagnosticData, currentTime, (TimestampWrapper) token, policy);
		} else if (Context.REVOCATION.equals(context)) {
			aav = new RevocationAcceptanceValidation(diagnosticData, currentTime, (RevocationWrapper) token, policy);
		} else {
			logger.info("Unsupported context " + context);
		}
		return aav != null ? aav.execute() : null;
	}

}
