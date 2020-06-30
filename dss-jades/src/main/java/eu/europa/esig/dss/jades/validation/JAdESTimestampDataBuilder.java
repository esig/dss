package eu.europa.esig.dss.jades.validation;

import org.jose4j.lang.JoseException;

import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.validation.timestamp.TimestampDataBuilder;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public class JAdESTimestampDataBuilder implements TimestampDataBuilder {

	private final JAdESSignature signature;

	public JAdESTimestampDataBuilder(JAdESSignature signature) {
		this.signature = signature;
	}

	@Override
	public DSSDocument getContentTimestampData(TimestampToken timestampToken) {
		try {
			// TODO sigD
			return new InMemoryDocument(JAdESUtils.toBase64Url(signature.getJws().getPayloadBytes()).getBytes());
		} catch (JoseException e) {
			throw new DSSException("Unable to extract the payload", e);
		}
	}

	@Override
	public DSSDocument getSignatureTimestampData(TimestampToken timestampToken) {
		// not supported
		return null;
	}

	@Override
	public DSSDocument getTimestampX1Data(TimestampToken timestampToken) {
		// not supported
		return null;
	}

	@Override
	public DSSDocument getTimestampX2Data(TimestampToken timestampToken) {
		// not supported
		return null;
	}

	@Override
	public DSSDocument getArchiveTimestampData(TimestampToken timestampToken) {
		// not supported
		return null;
	}

}
