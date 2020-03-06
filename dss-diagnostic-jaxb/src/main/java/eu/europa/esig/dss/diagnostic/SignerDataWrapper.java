package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;

public class SignerDataWrapper {
	
	private final XmlSignerData signerData;
	
	public SignerDataWrapper(final XmlSignerData signerData) {
		this.signerData = signerData;
	}
	
	public String getId() {
		return signerData.getId();
	}
	
	public String getReferencedName() {
		return signerData.getReferencedName();
	}
	
	public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
		return signerData.getDigestAlgoAndValue();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((getId() == null) ? 0 : getId().hashCode());
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
		SignerDataWrapper other = (SignerDataWrapper) obj;
		if (getId() == null) {
			if (other.getId() != null)
				return false;
		} else if (!getId().equals(other.getId()))
			return false;
		return true;
	}
	
	@Override
	public String toString() {
		return "SignerData Id='" + getId() + "'";
	}

}
