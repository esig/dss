package eu.europa.esig.dss.xades;

import eu.europa.esig.dss.DSSDocument;

public interface SignatureProfile {

	DSSDocument signDocument(DSSDocument toSignDocument, XAdESSignatureParameters parameters, byte[] signatureValue);

}
