package eu.europa.esig.dss.asic.signature.asics;

import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.utils.Utils;

public abstract class AbstractGetDataToSignASiCSWithXAdES extends AbstractGetDataToSignASiCS {

	protected String getSignatureFileName(final ASiCParameters asicParameters) {
		if (Utils.isStringNotBlank(asicParameters.getSignatureFileName())) {
			return "META-INF/" + asicParameters.getSignatureFileName();
		}
		return "META-INF/signatures.xml";
	}

}
