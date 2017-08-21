package eu.europa.esig.dss.signature.policy;

import java.util.List;

public interface AlgAndLength extends SignPolExtensions {

	String getAlgID();

	Integer getMinKeyLength();

	List<SignPolExtn> getSignPolExtensions();

}