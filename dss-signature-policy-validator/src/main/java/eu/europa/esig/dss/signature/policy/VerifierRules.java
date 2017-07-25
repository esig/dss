package eu.europa.esig.dss.signature.policy;

import java.util.List;

public interface VerifierRules {

	List<String> getMandatedUnsignedAttr();

	List<SignPolExtn> getSignPolExtensions();

}