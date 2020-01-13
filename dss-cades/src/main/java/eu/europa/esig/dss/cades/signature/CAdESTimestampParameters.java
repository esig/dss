package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.TimestampParameters;

@SuppressWarnings("serial")
public class CAdESTimestampParameters extends TimestampParameters {
	
	public CAdESTimestampParameters() {
	}
	
	public CAdESTimestampParameters(DigestAlgorithm digestAlgorithm) {
		super(digestAlgorithm);
	}

}
