package eu.europa.esig.dss.jades.requirements;

import java.util.Map;

import org.jose4j.jwx.CompactSerializer;

public abstract class AbstractJAdESCompactSignatureRequirementsCheck extends AbstractJAdESRequirementsCheck {
	
	@Override
	protected String getPayload(byte[] byteArray) throws Exception {
		String[] parts = CompactSerializer.deserialize(new String(byteArray));
		return parts[1];
	}
	
	@Override
	protected String getProtectedHeader(byte[] byteArray) throws Exception {
		String[] parts = CompactSerializer.deserialize(new String(byteArray));
		return parts[0];
	}
	
	@Override
	protected String getSignatureValue(byte[] byteArray) throws Exception {
		String[] parts = CompactSerializer.deserialize(new String(byteArray));
		return parts[2];
	}
	
	@Override
	protected Map<?, ?> getUnprotectedHeader(byte[] byteArray) throws Exception {
		// not supported
		return null;
	}
	
	@Override
	protected void checkUnprotectedHeader(Map<?, ?> unprotectedHeaderMap) throws Exception {
		// do nothing
	}

}
