package eu.europa.dss.signature.policy;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x509.NameConstraints;

public interface CertificateTrustPoint {

	X509Certificate getTrustpoint();

	int getPathLenConstraint();

	List<String> getAcceptablePolicySet();

	NameConstraints getNameConstraints();

	PolicyConstraints getPolicyConstraints();

}