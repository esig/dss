package eu.europa.esig.dss.xades;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.TimestampParameters;

@SuppressWarnings("serial")
public class XAdESTimestampParameters extends TimestampParameters {

	/**
	 * This is the default canonicalization method for XMLDSIG used for timestamps. Another complication arises because
	 * of the way that the default canonicalization algorithm
	 * handles namespace declarations; frequently a signed XML document needs to be embedded in another document; in
	 * this case the original canonicalization algorithm will not
	 * yield the same result as if the document is treated alone. For this reason, the so-called Exclusive
	 * Canonicalization, which serializes XML namespace declarations
	 * independently of the surrounding XML, was created.
	 */
	private String canonicalizationMethod = CanonicalizationMethod.EXCLUSIVE;
	
	public XAdESTimestampParameters() {
	}
	
	public XAdESTimestampParameters(DigestAlgorithm digestAlgorithm) {
		super(digestAlgorithm);
	}
	
	public XAdESTimestampParameters(DigestAlgorithm digestAlgorithm, String canonicalizationMethod) {
		super(digestAlgorithm);
		this.canonicalizationMethod = canonicalizationMethod;
	}

	public String getCanonicalizationMethod() {
		return canonicalizationMethod;
	}

	public void setCanonicalizationMethod(final String canonicalizationMethod) {
		this.canonicalizationMethod = canonicalizationMethod;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = (prime * result) + ((canonicalizationMethod == null) ? 0 : canonicalizationMethod.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (!super.equals(obj)) {
			return false;
		}
		XAdESTimestampParameters other = (XAdESTimestampParameters) obj;
		if (canonicalizationMethod == null) {
			if (other.canonicalizationMethod != null) {
				return false;
			}
		} else if (!canonicalizationMethod.equals(other.canonicalizationMethod)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "TimestampParameters {digestAlgorithm=" + digestAlgorithm.getName() + ", canonicalizationMethod=" + canonicalizationMethod + "}";
	}

}
