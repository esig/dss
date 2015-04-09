package eu.europa.esig.dss.xades;

import eu.europa.esig.dss.DSSDocument;

public interface SignatureBuilder {

	DSSDocument signDocument(byte[] signatureValue);

}
