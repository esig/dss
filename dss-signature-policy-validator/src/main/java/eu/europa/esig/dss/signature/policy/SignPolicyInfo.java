package eu.europa.esig.dss.signature.policy;

import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x509.GeneralNames;

public interface SignPolicyInfo {

	String getSignPolicyIdentifier();

	Date getDateOfIssue();

	GeneralNames getPolicyIssuerName();

	String getFieldOfApplication();

	SignatureValidationPolicy getSignatureValidationPolicy();

	List<SignPolExtn> getSignPolExtensions();

}