package eu.europa.esig.dss.diagnostic;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocationRef;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;

/**
 * Represents a revocation data wrapper
 *
 */
public class RevocationRefWrappper {
	
	private final XmlRevocationRef revocationRef;
	
	public RevocationRefWrappper(final XmlRevocationRef revocationRef) {
		this.revocationRef = revocationRef;
	}
	
	/**
	 * Returns a list of revocation reference origins
	 * 
	 * @return a list of {@link RevocationRefOrigin}s
	 */
	public List<RevocationRefOrigin> getOrigins() {
		return revocationRef.getOrigins();
	}

	/**
	 * Returns revocation ref production time if present
	 * 
	 * @return {@link Date}
	 */
	public Date getProductionTime() {
		return revocationRef.getProducedAt();
	}
	
	/**
	 * Returns responser's ID name if present
	 * 
	 * @return {@link String}
	 */
	public String getResponderIdName() {
		return revocationRef.getResponderIdName();
	}
	
	/**
	 * Returns responser's ID key if present
	 * 
	 * @return a byte array
	 */
	public byte[] getResponderIdKey() {
		return revocationRef.getResponderIdKey();
	}
	
	/**
	 * Returns digest algo and value
	 * 
	 * @return {@link XmlDigestAlgoAndValue}
	 */
	public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
		return revocationRef.getDigestAlgoAndValue();
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		if (revocationRef != null) {
			result = prime * result + ((revocationRef.getOrigins() == null) ? 0 : revocationRef.getOrigins().hashCode());
			result = prime * result + ((revocationRef.getProducedAt() == null) ? 0 : revocationRef.getProducedAt().hashCode());
			result = prime * result + ((revocationRef.getResponderIdName() == null) ? 0 : revocationRef.getResponderIdName().hashCode());
			result = prime * result + ((revocationRef.getResponderIdKey() == null) ? 0 : Arrays.hashCode(revocationRef.getResponderIdKey()));
			if (revocationRef.getDigestAlgoAndValue() != null) {
				result = prime * result + ((revocationRef.getDigestAlgoAndValue().getDigestMethod() == null) ? 0 : 
					revocationRef.getDigestAlgoAndValue().getDigestMethod().hashCode());
				result = prime * result + ((revocationRef.getDigestAlgoAndValue().getDigestValue() == null) ? 0 : 
					Arrays.hashCode(revocationRef.getDigestAlgoAndValue().getDigestValue()));
			}
		}
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		RevocationRefWrappper other = (RevocationRefWrappper) obj;
		if (revocationRef == null) {
			if (other.revocationRef != null)
				return false;
		} else if (other.revocationRef == null)
			return false;
		if (revocationRef.getOrigins() == null) {
			if (other.revocationRef.getOrigins() != null)
				return false;
		} else if (!revocationRef.getOrigins().equals(other.revocationRef.getOrigins()))
			return false;
		if (revocationRef.getProducedAt() == null) {
			if (other.revocationRef.getProducedAt() != null)
				return false;
		} else if (!revocationRef.getProducedAt().equals(other.revocationRef.getProducedAt()))
			return false;
		if (revocationRef.getResponderIdName() == null) {
			if (other.revocationRef.getResponderIdName() != null)
				return false;
		} else if (!revocationRef.getResponderIdName().equals(other.revocationRef.getResponderIdName()))
			return false;
		if (revocationRef.getResponderIdKey() == null) {
			if (other.revocationRef.getResponderIdKey() != null)
				return false;
		} else if (!Arrays.equals(revocationRef.getResponderIdKey(), other.revocationRef.getResponderIdKey()))
			return false;
		if (revocationRef.getDigestAlgoAndValue() == null) {
			if (other.revocationRef.getDigestAlgoAndValue() != null)
				return false;
		} else if (other.revocationRef.getDigestAlgoAndValue() == null)
			return false;
		if (revocationRef.getDigestAlgoAndValue().getDigestMethod() == null) {
			if (other.revocationRef.getDigestAlgoAndValue().getDigestMethod() != null)
				return false;
		} else if (!revocationRef.getDigestAlgoAndValue().getDigestMethod().equals(other.revocationRef.getDigestAlgoAndValue().getDigestMethod()))
			return false;
		if (revocationRef.getDigestAlgoAndValue().getDigestValue() == null) {
			if (other.revocationRef.getDigestAlgoAndValue().getDigestValue() != null)
				return false;
		} else if (!Arrays.equals(revocationRef.getDigestAlgoAndValue().getDigestValue(), other.revocationRef.getDigestAlgoAndValue().getDigestValue()))
			return false;
		return true;
	}
	
	@Override
	public String toString() {
		if (revocationRef != null) {
			return "RevocationRefWrapper Origins='" + revocationRef.getOrigins().toArray() + "',  ProductionTime='" + revocationRef.getProducedAt() + 
					"', responderIdName='" + revocationRef.getResponderIdName() + "'";
		} else {
			return "RevocationRefWrapper revocationRef=" + revocationRef;
		}
	}

}
