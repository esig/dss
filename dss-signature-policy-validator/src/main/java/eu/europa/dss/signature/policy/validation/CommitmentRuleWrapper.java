package eu.europa.dss.signature.policy.validation;

import java.util.List;

import eu.europa.dss.signature.policy.AlgorithmConstraintSet;
import eu.europa.dss.signature.policy.AttributeTrustCondition;
import eu.europa.dss.signature.policy.CommitmentRule;
import eu.europa.dss.signature.policy.CommitmentType;
import eu.europa.dss.signature.policy.CommonRules;
import eu.europa.dss.signature.policy.SignPolExtn;
import eu.europa.dss.signature.policy.SignerAndVerifierRules;
import eu.europa.dss.signature.policy.SigningCertTrustCondition;
import eu.europa.dss.signature.policy.TimestampTrustCondition;
import eu.europa.dss.signature.policy.asn1.ASN1CommitmentRule;

public class CommitmentRuleWrapper extends ASN1CommitmentRule {

	private CommitmentRule cmmtRule;
	private CommonRules commonRules;

	public CommitmentRuleWrapper(CommitmentRule cmmtRule, CommonRules commonRules) {
		this.cmmtRule = cmmtRule;
		this.commonRules = commonRules;
	}

	public List<CommitmentType> getSelCommitmentTypes() {
		return cmmtRule.getSelCommitmentTypes();
	}

	public SignerAndVerifierRules getSignerAndVeriferRules() {
		return commonRules.getSignerAndVeriferRules() != null? commonRules.getSignerAndVeriferRules(): cmmtRule.getSignerAndVeriferRules();
	}

	public SigningCertTrustCondition getSigningCertTrustCondition() {
		return commonRules.getSigningCertTrustCondition() != null? commonRules.getSigningCertTrustCondition(): cmmtRule.getSigningCertTrustCondition();
	}

	public TimestampTrustCondition getTimeStampTrustCondition() {
		return commonRules.getTimeStampTrustCondition() != null? commonRules.getTimeStampTrustCondition(): cmmtRule.getTimeStampTrustCondition();
	}

	public AttributeTrustCondition getAttributeTrustCondition() {
		// Should I return both?
		return cmmtRule.getAttributeTrustCondition();
	}

	public AlgorithmConstraintSet getAlgorithmConstraintSet() {
		// Should I return both?
		return cmmtRule.getAlgorithmConstraintSet();
	}

	public List<SignPolExtn> getSignPolExtensions() {
		// Should I return both?
		return cmmtRule.getSignPolExtensions();
	}

}
