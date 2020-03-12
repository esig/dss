package eu.europa.esig.dss.diagnostic;

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
		return certificateRef.getIssuerName();
	}
	
	/**
	 * Returns SKI of the certificate
	 * (SHA-1 of the certificate's public key)
	 * 
	 * @return a byte array
	 */
	public byte[] getSki() {
		return certificateRef.getSki();
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

}
