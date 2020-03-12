package eu.europa.esig.dss.diagnostic;

import java.util.Objects;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanToken;

public class OrphanTokenWrapper {

	private final XmlOrphanToken orphanToken;
	
	public OrphanTokenWrapper(final XmlOrphanToken orphanToken) {
		Objects.requireNonNull(orphanToken, "XmlOrphanToken cannot be null!");
		this.orphanToken = orphanToken;
	}
	
	/**
	 * Returns identifier of the orphan token
	 * 
	 * @return {@link String} id
	 */
	public String getId() {
		return orphanToken.getId();
	}
	
	/**
	 * Returns base64-encoded byte array of the token
	 * 
	 * @return
	 */
	public byte[] getBinaries() {
		return orphanToken.getBase64Encoded();
	}

	/**
	 * Returns digest of the token
	 * 
	 * @return {@link XmlDigestAlgoAndValue}
	 */
	public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
		return orphanToken.getDigestAlgoAndValue();
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((orphanToken == null) ? 0 : orphanToken.getId().hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof OrphanTokenWrapper))
			return false;
		OrphanTokenWrapper other = (OrphanTokenWrapper) obj;
		if (getId() == null) {
			if (other.getId() != null)
				return false;
		} else if (!getId().equals(other.getId()))
			return false;
		return true;
	}
	
	@Override
	public String toString() {
		return "OrphanTokenWrappper Class='" + getClass() + "', Id='" + getId() + "'";
	}

}
