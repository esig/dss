package eu.europa.esig.dss.EN319102.validation.bbb;

import java.util.Date;

import eu.europa.esig.dss.EN319102.validation.bbb.cv.CryptographicVerification;
import eu.europa.esig.dss.EN319102.validation.bbb.isc.IdentificationOfTheSigningCertificate;
import eu.europa.esig.dss.EN319102.validation.bbb.sav.AbstractAcceptanceValidation;
import eu.europa.esig.dss.EN319102.validation.bbb.sav.SignatureAcceptanceValidation;
import eu.europa.esig.dss.EN319102.validation.bbb.sav.TimestampAcceptanceValidation;
import eu.europa.esig.dss.EN319102.validation.bbb.vci.ValidationContextInitialization;
import eu.europa.esig.dss.EN319102.validation.bbb.xcv.X509CertificateValidation;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.EN319102.wrappers.CertificateWrapper;
import eu.europa.esig.dss.EN319102.wrappers.DiagnosticData;
import eu.europa.esig.dss.EN319102.wrappers.SignatureWrapper;
import eu.europa.esig.dss.EN319102.wrappers.TimestampWrapper;
import eu.europa.esig.dss.EN319102.wrappers.TokenProxy;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlInfo;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlVCI;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.policy.rules.Indication;

/**
 * 5.2 Basic building blocks
 */
public class BasicBuildingBlocks {

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

		/**
		 * 5.2.2 Format Checking
		 */
		// TODO

		/**
		 * 5.2.3 Identification of the signing certificate
		 */
		XmlISC isc = executeIdentificationOfTheSigningCertificate();
		result.setISC(isc);

		XmlConclusion iscConclusion = isc.getConclusion();
		if (!Indication.VALID.equals(iscConclusion.getIndication())) {
			result.setConclusion(iscConclusion);
			return result;
		}
		XmlInfo conclusionInfo = new XmlInfo();
		conclusionInfo.setCertificateId(token.getSigningCertificateId());
		isc.getConclusion().getInfo().add(conclusionInfo);

		/**
		 * 5.2.4 Validation context initialization
		 */
		XmlVCI vci = executeValidationContextInitialization();
		if (vci != null) {
			result.setVCI(vci);
			XmlConclusion vciConclusion = vci.getConclusion();
			if (!Indication.VALID.equals(vciConclusion.getIndication())) {
				result.setConclusion(vciConclusion);
				return result;
			}
		}

		/**
		 * 5.2.5 Revocation freshness checker
		 */
		// TODO ?

		/**
		 * 5.2.6 X.509 certificate validation
		 */
		XmlXCV xcv = executeX509CertificateValidation();
		result.setXCV(xcv);
		XmlConclusion xcvConclusion = xcv.getConclusion();
		if (!Indication.VALID.equals(xcvConclusion.getIndication())) {
			result.setConclusion(xcvConclusion);
			return result;
		}

		/**
		 * 5.2.7 Cryptographic verification
		 */
		XmlCV cv = executeCryptographicVerification();
		result.setCV(cv);

		XmlConclusion cvConclusion = cv.getConclusion();
		if (!Indication.VALID.equals(cvConclusion.getIndication())) {
			result.setConclusion(cvConclusion);
			return result;
		}

		/**
		 * 5.2.8 Signature acceptance validation (SAV)
		 */
		XmlSAV sav = executeSignatureAcceptanceValidation();
		result.setSAV(sav);
		XmlConclusion savConclusion = sav.getConclusion();
		if (!Indication.VALID.equals(savConclusion.getIndication())) {
			result.setConclusion(cvConclusion);
			return result;
		}

		XmlConclusion conclusion = new XmlConclusion();
		conclusion.setIndication(Indication.VALID);
		result.setConclusion(conclusion);

		return result;
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
		CryptographicVerification cv = new CryptographicVerification(token, context, policy);
		return cv.execute();
	}

	private XmlXCV executeX509CertificateValidation() {
		// Not null because of ISC
		CertificateWrapper certificate = diagnosticData.getUsedCertificateByIdNullSafe(token.getSigningCertificateId());
		X509CertificateValidation xcv = new X509CertificateValidation(diagnosticData, certificate, currentTime, context, policy);
		return xcv.execute();
	}

	private XmlSAV executeSignatureAcceptanceValidation() {
		AbstractAcceptanceValidation<?> aav = null;
		if (Context.SIGNATURE.equals(context) || Context.COUNTER_SIGNATURE.equals(context)) {
			aav = new SignatureAcceptanceValidation(diagnosticData, currentTime, (SignatureWrapper) token, context, policy);
		} else if (Context.TIMESTAMP.equals(context)) {
			aav = new TimestampAcceptanceValidation(diagnosticData, currentTime, (TimestampWrapper) token, policy);
		}
		return aav.execute();
	}

}
