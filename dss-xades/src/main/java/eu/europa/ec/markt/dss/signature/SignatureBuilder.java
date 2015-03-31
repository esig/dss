package eu.europa.ec.markt.dss.signature;

public interface SignatureBuilder {

	DSSDocument signDocument(byte[] signatureValue);

}
