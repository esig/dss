package eu.europa.dss.signature.policy;

import java.util.List;

public interface CommonRules {

	SignerAndVerifierRules getSignerAndVeriferRules();

	SigningCertTrustCondition getSigningCertTrustCondition();

	TimestampTrustCondition getTimeStampTrustCondition();

	AttributeTrustCondition getAttributeTrustCondition();

	AlgorithmConstraintSet getAlgorithmConstraintSet();

	List<SignPolExtn> getSignPolExtensions();

}