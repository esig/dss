package eu.europa.dss.signature.policy;

import java.util.List;

public interface SignatureValidationPolicy {

	SigningPeriod getSigningPeriod();

	CommonRules getCommonRules();

	List<CommitmentRule> getCommitmentRules();

	List<SignPolExtn> getSignPolExtensions();

}