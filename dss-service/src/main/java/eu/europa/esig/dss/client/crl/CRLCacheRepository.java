package eu.europa.esig.dss.client.crl;

import eu.europa.esig.dss.crl.CRLValidity;

public interface CRLCacheRepository {

	public CRLValidity findCrl(String key);

	public void insertCrl(String key, CRLValidity token);

	public void updateCrl(String key, CRLValidity token);

}
