package eu.europa.esig.dss.validation.timestamp;

import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.scope.SignatureScope;

public interface TimestampValidator extends DocumentValidator {
	
	/**
	 * Returns a map of detached timestamps and their signatureScopes
	 * 
	 * @return a map between {@link TimestampToken}s and lists of {@link SignatureScope}s
	 */
	Map<TimestampToken, List<SignatureScope>> getTimestamps();
	
}
