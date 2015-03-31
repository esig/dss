package eu.europa.ec.markt.dss.parameter;

import eu.europa.ec.markt.dss.signature.DSSDocument;

public interface SignatureProfile {

	DSSDocument signDocument(DSSDocument toSignDocument, XAdESSignatureParameters parameters, byte[] signatureValue);

}
