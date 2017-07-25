package eu.europa.esig.dss.signature.policy;

import java.util.List;

public interface RevReq {

	EnuRevReq getEnuRevReq();

	List<SignPolExtn> getExRevReq();

}