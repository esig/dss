package eu.europa.esig.dss.signature.policy;

import java.util.List;

public interface VerifierRules extends SignPolExtensions {

	List<String> getMandatedUnsignedAttr();

	List<SignPolExtn> getSignPolExtensions();

}