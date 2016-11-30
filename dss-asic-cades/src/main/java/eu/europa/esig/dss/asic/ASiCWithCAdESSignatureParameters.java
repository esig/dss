package eu.europa.esig.dss.asic;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;

public class ASiCWithCAdESSignatureParameters extends CAdESSignatureParameters {

	private static final long serialVersionUID = -830012801924753709L;

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
