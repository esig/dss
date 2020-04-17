package eu.europa.esig.dss.diagnostic;

import java.util.Arrays;

import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;

/**
 * Represents a certificate reference wrapper
 *
 */
public class CertificateRefWrapper {
	
	private final XmlCertificateRef certificateRef;
	
	public CertificateRefWrapper(final XmlCertificateRef certificateRef) {
		this.certificateRef = certificateRef;
	}
	
	/**
	 * Returns a certificate reference origin
	 * 
	 * @return {@link CertificateRefOrigin}
	 */
	public CertificateRefOrigin getOrigin() {
		return certificateRef.getOrigin();
	}
	
	/**
	 * Returns IssuerSerial's binaries
	 * 
	 * @return a byte array
	 */
	public byte[] getIssuerSerial() {
		return certificateRef.getIssuerSerial();
	}

	/**
	 * Returns IssuerName
	 * 
	 * @return {@link String}
	 */
	public String getIssuerName() {
		if (certificateRef.getSerialInfo() != null) {
			return certificateRef.getSerialInfo().getIssuerName();
		}
		return null;
	}
	
	/**
	 * Returns SKI of the certificate
	 * (SHA-1 of the certificate's public key)
	 * 
	 * @return a byte array
	 */
	public byte[] getSki() {
		if (certificateRef.getSerialInfo() != null) {
			return certificateRef.getSerialInfo().getSki();
		}
		return null;
	}
	
	/**
	 * Returns digest algo and value
	 * 
	 * @return {@link XmlDigestAlgoAndValue}
	 */
	public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
		return certificateRef.getDigestAlgoAndValue();
	}
	
	@Override
	public String toString() {
		if (certificateRef != null) {
			return "CertificateRefWrapper Origin='" + certificateRef.getOrigin() + "'";
		} else {
			return "CertificateRefWrapper certificateRef=" + certificateRef;
		}
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((certificateRef.getOrigin() == null) ? 0 : certificateRef.getOrigin().hashCode());
		result = prime * result + ((certificateRef.getIssuerSerial() == null) ? 0 : Arrays.hashCode(certificateRef.getIssuerSerial()));
		result = prime * result + ((certificateRef.getSerialInfo() == null || certificateRef.getSerialInfo().getIssuerName() == null) ?
				0 : certificateRef.getSerialInfo().getIssuerName().hashCode());
		result = prime * result + ((certificateRef.getSerialInfo() == null || certificateRef.getSerialInfo().getSki() == null) ?
				0 : Arrays.hashCode(certificateRef.getSerialInfo().getSki()));
		result = prime * result + ((certificateRef.getDigestAlgoAndValue() == null || certificateRef.getDigestAlgoAndValue().getDigestMethod() == null) ?
				0 : certificateRef.getDigestAlgoAndValue().getDigestMethod().hashCode());
		result = prime * result + ((certificateRef.getDigestAlgoAndValue() == null || certificateRef.getDigestAlgoAndValue().getDigestValue() == null) ?
				0 : Arrays.hashCode(certificateRef.getDigestAlgoAndValue().getDigestValue()));
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		CertificateRefWrapper other = (CertificateRefWrapper) obj;
		if (certificateRef == null) {
			if (other.certificateRef != null) {
				return false;
			}
		} else if (other.certificateRef == null) {
			return false;
		}
		if (certificateRef.getOrigin() == null) {
			if (other.certificateRef.getOrigin() != null) {
				return false;
			}
		} else if (!certificateRef.getOrigin().equals(other.certificateRef.getOrigin())) {
			return false;
		}
		if (certificateRef.getIssuerSerial() == null) {
			if (other.certificateRef.getIssuerSerial() != null) {
				return false;
			}
		} else if (!Arrays.equals(certificateRef.getIssuerSerial(), other.certificateRef.getIssuerSerial())) {
			return false;
		}
		if (certificateRef.getSerialInfo() == null) {
			if (other.certificateRef.getSerialInfo() != null) {
				return false;
			}
		} else {
			if (certificateRef.getSerialInfo().getIssuerName() == null) {
				if (other.certificateRef.getSerialInfo().getIssuerName() != null) {
					return false;
				}
			} else if (!certificateRef.getSerialInfo().getIssuerName().equals(other.certificateRef.getSerialInfo().getIssuerName())) {
				return false;
			}
			if (certificateRef.getSerialInfo().getSki() == null) {
				if (other.certificateRef.getSerialInfo().getSki() != null) {
					return false;
				}
			} else if (!Arrays.equals(certificateRef.getSerialInfo().getSki(), other.certificateRef.getSerialInfo().getSki())) {
				return false;
			}
		}
		if (certificateRef.getDigestAlgoAndValue() == null) {
			if (other.certificateRef.getDigestAlgoAndValue() != null) {
				return false;
			}
		} else {
			if (certificateRef.getDigestAlgoAndValue().getDigestMethod() == null) {
				if (other.certificateRef.getDigestAlgoAndValue().getDigestMethod() != null) {
					return false;
				}
			} else if (!certificateRef.getDigestAlgoAndValue().getDigestMethod().equals(other.certificateRef.getDigestAlgoAndValue().getDigestMethod())) {
				return false;
			}
			if (certificateRef.getDigestAlgoAndValue().getDigestValue() == null) {
				if (other.certificateRef.getDigestAlgoAndValue().getDigestValue() != null) {
					return false;
				}
			} else if (!Arrays.equals(certificateRef.getDigestAlgoAndValue().getDigestValue(), other.certificateRef.getDigestAlgoAndValue().getDigestValue())) {
				return false;
			}
		}
		return true;
	}

}
