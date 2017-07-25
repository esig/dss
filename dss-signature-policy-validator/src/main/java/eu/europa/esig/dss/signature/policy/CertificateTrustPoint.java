package eu.europa.esig.dss.signature.policy;

import java.security.cert.X509Certificate;
import java.util.Set;

import org.bouncycastle.asn1.x509.NameConstraints;

public interface CertificateTrustPoint {

	X509Certificate getTrustpoint();

	Integer getPathLenConstraint();

	Set<String> getAcceptablePolicySet();

	NameConstraints getNameConstraints();

	PolicyConstraints getPolicyConstraints();

}