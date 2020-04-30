package eu.europa.esig.dss.crl.x509.impl;

import java.security.cert.CRLException;
import java.security.cert.X509CRL;

import eu.europa.esig.dss.crl.CRLBinary;

/**
 * The X509 implementation of CRLBinary class
 *
 */
public final class X509CRLBinary extends CRLBinary {
	
	private static final long serialVersionUID = -7740972876494867754L;

	/**
	 * The default constructor to define CRLBinary
	 * 
	 * @param x509CRL {@link X509CRL}
	 * @throws CRLException
	 * 						if in exception occurs
	 */
	public X509CRLBinary(X509CRL x509CRL) throws CRLException {
		super(x509CRL.getEncoded());
	}

}
