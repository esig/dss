package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.validation.SignatureOCSPSource;

public class JAdESOCSPSource extends SignatureOCSPSource {

	private static final long serialVersionUID = -2302581952761566688L;
	
	// Not supported

	@Override
	public void appendContainedOCSPResponses() {
	}

}
