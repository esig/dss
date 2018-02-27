package eu.europa.esig.dss.validation;

import java.util.HashMap;
import java.util.Map;

import eu.europa.esig.dss.CertificatePolicyOids;
import eu.europa.esig.dss.ExtendedKeyUsageOids;
import eu.europa.esig.dss.OidDescription;
import eu.europa.esig.dss.QCStatementOids;

public class OidRepository {

	private static final Map<String, String> repository = new HashMap<String, String>();

	static {
		for (OidDescription oid : CertificatePolicyOids.values()) {
			repository.put(oid.getOid(), oid.getDescription());
		}
		for (OidDescription oid : QCStatementOids.values()) {
			repository.put(oid.getOid(), oid.getDescription());
		}
		for (ExtendedKeyUsageOids oid : ExtendedKeyUsageOids.values()) {
			repository.put(oid.getOid(), oid.getDescription());
		}
	}

	private OidRepository() {
	}

	public static String getDescription(String oid) {
		return repository.get(oid);
	}

}
