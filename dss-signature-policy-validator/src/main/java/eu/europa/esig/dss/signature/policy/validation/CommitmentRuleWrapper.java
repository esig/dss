package eu.europa.esig.dss.signature.policy.validation;

import java.util.List;

import eu.europa.esig.dss.signature.policy.AlgorithmConstraintSet;
import eu.europa.esig.dss.signature.policy.AttributeTrustCondition;
import eu.europa.esig.dss.signature.policy.CommitmentRule;
import eu.europa.esig.dss.signature.policy.CommitmentType;
import eu.europa.esig.dss.signature.policy.CommonRules;
import eu.europa.esig.dss.signature.policy.SignPolExtn;
import eu.europa.esig.dss.signature.policy.SignerAndVerifierRules;
import eu.europa.esig.dss.signature.policy.SigningCertTrustCondition;
import eu.europa.esig.dss.signature.policy.TimestampTrustCondition;
import eu.europa.esig.dss.signature.policy.asn1.ASN1CommitmentRule;

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
		return commonRules.getAttributeTrustCondition() != null? commonRules.getAttributeTrustCondition(): cmmtRule.getAttributeTrustCondition();
	}

	public AlgorithmConstraintSet getAlgorithmConstraintSet() {
		return commonRules.getAlgorithmConstraintSet() != null? commonRules.getAlgorithmConstraintSet(): cmmtRule.getAlgorithmConstraintSet();
	}

	public List<SignPolExtn> getSignPolExtensions() {
		return commonRules.getSignPolExtensions() != null? commonRules.getSignPolExtensions(): cmmtRule.getSignPolExtensions();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((cmmtRule == null) ? 0 : cmmtRule.hashCode());
		result = prime * result + ((commonRules == null) ? 0 : commonRules.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		CommitmentRuleWrapper other = (CommitmentRuleWrapper) obj;
		if (cmmtRule == null) {
			if (other.cmmtRule != null)
				return false;
		} else if (!cmmtRule.equals(other.cmmtRule))
			return false;
		if (commonRules == null) {
			if (other.commonRules != null)
				return false;
		} else if (!commonRules.equals(other.commonRules))
			return false;
		return true;
	}

}
