package eu.europa.ec.markt.dss.parameter;

public class ASiCSignatureParameters extends SignatureParameters {

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
