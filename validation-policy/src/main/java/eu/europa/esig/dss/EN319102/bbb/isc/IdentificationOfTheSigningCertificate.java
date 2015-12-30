package eu.europa.esig.dss.EN319102.bbb.isc;

import eu.europa.esig.dss.EN319102.bbb.AbstractBasicBuildingBlock;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.bbb.isc.checks.DigestValueMatchCheck;
import eu.europa.esig.dss.EN319102.bbb.isc.checks.DigestValuePresentCheck;
import eu.europa.esig.dss.EN319102.bbb.isc.checks.IssuerSerialMatchCheck;
import eu.europa.esig.dss.EN319102.bbb.isc.checks.SigningCertificateAttributePresentCheck;
import eu.europa.esig.dss.EN319102.bbb.isc.checks.SigningCertificateRecognitionCheck;
import eu.europa.esig.dss.EN319102.bbb.isc.checks.SigningCertificateSignedCheck;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.validation.TokenProxy;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.jaxb.policy.LevelConstraint;

/**
 * 5.2.3 Identification of the signing certificate This building block is
 * responsible for identifying the signing certificate that will be used to
 * validate the signature. In case of success, the output shall be the signing
 * certificate. In case the signing certificate cannot be identified, the output
 * shall be the indication INDETERMINATE and the sub-indication
 * NO_SIGNING_CERTIFICATE_FOUND.
 *
 * The common way to unambiguously identify the signing certificate is by using
 * a property/attribute of the signature containing a reference to it (see
 * clause 4.2.5.2). The certificate can either be found in the signature or it
 * can be obtained using external sources. The signing certificate can also be
 * provided by the DA. If no certificate can be retrieved, the building block
 * shall return the indication INDETERMINATE and the sub-indication
 * NO_SIGNING_CERTIFICATE_FOUND. The signing certificate shall be checked
 * against all references present in the signature attributes, since one of
 * these references is a reference to the signing certificate (see clause
 * 4.2.5.2). The following steps are performed: 1) If the signature format used
 * contains a way to directly identify the reference to the signers' certificate
 * in the attribute, the building block shall check that the digest of the
 * certificate referenced matches the result of digesting the signing
 * certificate with the algorithm indicated; if they match, the building block
 * shall return the signing certificate. Otherwise, the building block shall go
 * to step 2. 2) The building block shall take the first reference and shall
 * check that the digest of the certificate referenced matches the result of
 * digesting the signing certificate with the algorithm indicated. If they do
 * not match, the building block shall take the next element and shall repeat
 * this step until a matching element has been found or all elements have been
 * checked. If they do match, the building block shall continue with step 3. If
 * the last element is reached without finding any match, the validation of this
 * property shall be taken as failed and the building block shall return the
 * indication INDETERMINATE with the sub-indication
 * NO_SIGNING_CERTIFICATE_FOUND. 3) If the issuer and the serial number are
 * additionally present in that reference, the details of the issuer's name and
 * the serial number of the IssuerSerial element may be compared with those
 * indicated in the signing certificate: if they do not match, an additional
 * warning shall be returned with the output. 4) The building block shall return
 * the signing certificate
 */
public class IdentificationOfTheSigningCertificate extends AbstractBasicBuildingBlock<XmlISC> {

	private final DiagnosticData diagnosticData;
	private final TokenProxy token;

	private final ValidationPolicy validationPolicy;

	public IdentificationOfTheSigningCertificate(DiagnosticData diagnosticData, TokenProxy token, ValidationPolicy validationPolicy) {
		super(new XmlISC());

		this.diagnosticData = diagnosticData;
		this.token = token;
		this.validationPolicy = validationPolicy;
	}

	@Override
	protected void initChain() {
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

}
