package eu.europa.dss.signature.policy;

public interface SignerAndVerifierRules {

	SignerRules getSignerRules();

	VerifierRules getVerifierRules();

}