package eu.europa.esig.dss.signature.policy;

public interface SignerAndVerifierRules {

	SignerRules getSignerRules();

	VerifierRules getVerifierRules();

}