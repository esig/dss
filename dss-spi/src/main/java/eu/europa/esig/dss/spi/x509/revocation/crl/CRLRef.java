/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.x509.revocation.crl;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import org.bouncycastle.asn1.esf.CrlIdentifier;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.x500.X500Name;

import java.math.BigInteger;
import java.util.Date;

/**
 * Reference to a X509CRL
 *
 */
public final class CRLRef extends RevocationRef<CRL> {

	private static final long serialVersionUID = -6785644604097791548L;
	
	private X500Name crlIssuer;
	private Date crlIssuedTime;
	private BigInteger crlNumber;

	/**
	 * The default constructor for CRLRef.
	 *
	 * @param digest {@link Digest}
	 */
	public CRLRef(Digest digest) {
		this.digest = digest;
	}

	/**
	 * The default constructor for CRLRef.
	 *
	 * @param cmsRef {@link CrlValidatedID}
	 */
	public CRLRef(CrlValidatedID cmsRef) {
		try {
			final CrlIdentifier crlIdentifier = cmsRef.getCrlIdentifier();
			if (crlIdentifier != null) {
				this.crlIssuer = crlIdentifier.getCrlIssuer();
				this.crlIssuedTime = crlIdentifier.getCrlIssuedTime().getDate();
				this.crlNumber = crlIdentifier.getCrlNumber();
			}
			this.digest = DSSRevocationUtils.getDigest(cmsRef.getCrlHash());
		} catch (Exception e) {
			throw new DSSException("Unable to build CRLRef from CrlValidatedID", e);
		}
	}

	/**
	 * Gets CRL Issuer
	 *
	 * @return {@link X500Name}
	 */
	public X500Name getCrlIssuer() {
		return crlIssuer;
	}

	/**
	 * Sets CRL Issuer
	 *
	 * @param crlIssuer {@link X500Name}
	 */
	public void setCrlIssuer(X500Name crlIssuer) {
		this.crlIssuer = crlIssuer;
	}

	/**
	 * Gets CRL Issued time
	 *
	 * @return {@link Date}
	 */
	public Date getCrlIssuedTime() {
		return crlIssuedTime;
	}

	/**
	 * Sets CRL Issued time
	 *
	 * @param crlIssuedTime {@link Date}
	 */
	public void setCrlIssuedTime(Date crlIssuedTime) {
		this.crlIssuedTime = crlIssuedTime;
	}

	/**
	 * Gets CRL number
	 *
	 * @return {@link BigInteger}
	 */
	public BigInteger getCrlNumber() {
		return crlNumber;
	}

	/**
	 * Sets CRL number
	 *
	 * @param crlNumber {@link BigInteger}
	 */
	public void setCrlNumber(BigInteger crlNumber) {
		this.crlNumber = crlNumber;
	}

	@Override
	public String toString() {
		return "CRL Reference with Digest [" + super.toString() + "]";
	}

}
