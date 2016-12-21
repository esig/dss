package eu.europa.esig.dss.validation;

import java.util.HashMap;
import java.util.Map;

import eu.europa.esig.dss.CertificatePolicyOids;
import eu.europa.esig.dss.EtsiOid;
import eu.europa.esig.dss.QCStatementOids;

public class OidRepository {

	private static final Map<String, String> repository = new HashMap<String, String>();

	static {
		for (EtsiOid oid : CertificatePolicyOids.values()) {
			repository.put(oid.getOid(), oid.getDescription());
		}
		for (EtsiOid oid : QCStatementOids.values()) {
			repository.put(oid.getOid(), oid.getDescription());
		}
	}

	private OidRepository() {
	}

	public static String getDescription(String oid) {
		return repository.get(oid);
	}

}
