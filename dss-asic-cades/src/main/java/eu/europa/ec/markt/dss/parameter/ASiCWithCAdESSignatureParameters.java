package eu.europa.ec.markt.dss.parameter;

import eu.europa.ec.markt.dss.signature.SignatureLevel;

public class ASiCWithCAdESSignatureParameters extends CAdESSignatureParameters {

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

	@Override
	public void setSignatureLevel(SignatureLevel signatureLevel)  {
		super.setSignatureLevel(signatureLevel);

		ASiCParameters aSiC = aSiC();
		aSiC.containerForm = signatureLevel.getSignatureForm();
	}

}
