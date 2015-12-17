package eu.europa.esig.dss.EN319102.bbb.isc;

import eu.europa.esig.dss.EN319102.bbb.AbstractBasicBuildingBlock;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.bbb.isc.checks.DigestValueMatchCheck;
import eu.europa.esig.dss.EN319102.bbb.isc.checks.DigestValuePresentCheck;
import eu.europa.esig.dss.EN319102.bbb.isc.checks.IssuerSerialMatchCheck;
import eu.europa.esig.dss.EN319102.bbb.isc.checks.SigningCertificateAttributePresentCheck;
import eu.europa.esig.dss.EN319102.bbb.isc.checks.SigningCertificateRecognitionCheck;
import eu.europa.esig.dss.EN319102.bbb.isc.checks.SigningCertificateSignedCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.validation.TokenProxy;
import eu.europa.esig.dss.validation.policy.ValidationPolicy2;
import eu.europa.esig.dss.validation.policy.ValidationPolicy2.Context;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.jaxb.policy.LevelConstraint;

/**
 * 5.2.3 Identification of the signing certificate
 * This building block is responsible for identifying the signing certificate that will be used to validate the signature.
 * In case of success, the output shall be the signing certificate.
 * In case the signing certificate cannot be identified, the output shall be the indication INDETERMINATE and the sub-indication NO_SIGNING_CERTIFICATE_FOUND.
 */
public class IdentificationOfTheSigningCertificate extends AbstractBasicBuildingBlock<XmlISC> {

	private final DiagnosticData diagnosticData;
	private final TokenProxy token;

	private final ValidationPolicy2 validationPolicy;

	private ChainItem<XmlISC> firstItem;
	private XmlISC result = new XmlISC();

	public IdentificationOfTheSigningCertificate(DiagnosticData diagnosticData, TokenProxy token, ValidationPolicy2 validationPolicy) {
		this.diagnosticData = diagnosticData;
		this.token = token;
		this.validationPolicy = validationPolicy;
	}

	public void initChain() {
		ChainItem<XmlISC> item = firstItem = signingCertificateRecognition();
		item = item.setNextItem(signingCertificateSigned());
		item = item.setNextItem(signingCertificateAttributePresent());
		item = item.setNextItem(digestValuePresent());
		item = item.setNextItem(digestValueMatch());
		item = item.setNextItem(issuerSerialMatch());
	}

	private ChainItem<XmlISC> signingCertificateSigned() {
		LevelConstraint constraint = validationPolicy.getSigningCertificateSignedConstraint(Context.MAIN_SIGNATURE);
		return new SigningCertificateSignedCheck(result, token, constraint);
	}

	private ChainItem<XmlISC> signingCertificateRecognition() {
		LevelConstraint constraint = validationPolicy.getSigningCertificateRecognitionConstraint(Context.MAIN_SIGNATURE);
		return new SigningCertificateRecognitionCheck(result, token, diagnosticData, constraint);
	}

	private ChainItem<XmlISC> signingCertificateAttributePresent() {
		LevelConstraint constraint = validationPolicy.getSigningCertificateAttributePresentConstraint(Context.MAIN_SIGNATURE);
		return new SigningCertificateAttributePresentCheck(result, token, constraint);
	}

	private ChainItem<XmlISC> digestValuePresent() {
		LevelConstraint constraint = validationPolicy.getSigningCertificateDigestValuePresentConstraint(Context.MAIN_SIGNATURE);
		return new DigestValuePresentCheck(result, token, constraint);
	}

	private ChainItem<XmlISC> digestValueMatch() {
		LevelConstraint constraint = validationPolicy.getSigningCertificateDigestValueMatchConstraint(Context.MAIN_SIGNATURE);
		return new DigestValueMatchCheck(result, token, constraint);
	}

	private ChainItem<XmlISC> issuerSerialMatch() {
		LevelConstraint constraint = validationPolicy.getSigningCertificateIssuerSerialMatchConstraint(Context.MAIN_SIGNATURE);
		return new IssuerSerialMatchCheck(result, token, constraint);
	}

	public XmlISC execute() {
		firstItem.execute();
		return result;
	}

}
