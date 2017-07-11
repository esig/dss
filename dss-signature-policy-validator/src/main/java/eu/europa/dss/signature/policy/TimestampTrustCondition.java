package eu.europa.dss.signature.policy;

import org.bouncycastle.asn1.x509.NameConstraints;

public interface TimestampTrustCondition {

	CertificateTrustTrees getTtsCertificateTrustTrees();

	CertRevReq getTtsRevReq();

	NameConstraints getTtsNameConstraints();

	DeltaTime getCautionPeriod();

	DeltaTime getSignatureTimestampDelay();

}