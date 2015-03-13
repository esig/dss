package eu.europa.ec.markt.dss.signature;

import eu.europa.ec.markt.dss.parameter.SignatureParameters;

public interface SignatureProfile {

	DSSDocument signDocument(DSSDocument toSignDocument, SignatureParameters parameters, byte[] signatureValue);

}
