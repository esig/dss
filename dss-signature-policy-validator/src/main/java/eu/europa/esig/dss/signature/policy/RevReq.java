package eu.europa.esig.dss.signature.policy;

import java.util.List;

public interface RevReq extends SignPolExtensions {

	EnuRevReq getEnuRevReq();

	List<SignPolExtn> getSignPolExtensions();

}