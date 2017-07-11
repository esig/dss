package eu.europa.dss.signature.policy;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface SignaturePolicy {

	AlgorithmIdentifier getSignPolicyHashAlg();

	SignPolicyInfo getSignPolicyInfo();

	byte[] getSignPolicyHash();

}