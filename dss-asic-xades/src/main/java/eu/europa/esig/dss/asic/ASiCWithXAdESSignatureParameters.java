package eu.europa.esig.dss.asic;

import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class ASiCWithXAdESSignatureParameters extends XAdESSignatureParameters {

	private static final long serialVersionUID = 5004478692506008320L;

	/**
	 * The object representing the parameters related to ASiC from of the signature.
	 */
	private ASiCParameters aSiCParams = new ASiCParameters();

	public ASiCParameters aSiC() {
		if (aSiCParams == null) {
			aSiCParams = new ASiCParameters();
		}
		return aSiCParams;
	}

}
