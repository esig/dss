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

import java.math.BigInteger;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;

import org.bouncycastle.asn1.esf.CrlIdentifier;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.asn1.x500.X500Name;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;

/**
 * Reference to a X509CRL
 *
 */
public final class CRLRef extends RevocationRef {

	private static final long serialVersionUID = -6785644604097791548L;
	
	private X500Name crlIssuer;
	private Date crlIssuedTime;
	private BigInteger crlNumber;

	/**
	 * The default constructor for CRLRef.
	 */
	public CRLRef(Digest digest, RevocationRefOrigin origin) {
		this.digest = digest;
		this.origins = new HashSet<RevocationRefOrigin>(Arrays.asList(origin));
	}

	/**
	 * The default constructor for CRLRef.
	 *
	 * @param cmsRef
	 */
	public CRLRef(CrlValidatedID cmsRef, RevocationRefOrigin origin) {
		try {
			final CrlIdentifier crlIdentifier = cmsRef.getCrlIdentifier();
			if (crlIdentifier != null) {
				crlIssuer = crlIdentifier.getCrlIssuer();
				crlIssuedTime = crlIdentifier.getCrlIssuedTime().getDate();
				crlNumber = crlIdentifier.getCrlNumber();
			}
			final OtherHash crlHash = cmsRef.getCrlHash();

			DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(crlHash.getHashAlgorithm().getAlgorithm().getId());
			byte[] digestValue = crlHash.getHashValue();
			this.digest = new Digest(digestAlgorithm, digestValue);
			this.origins = new HashSet<RevocationRefOrigin>(Arrays.asList(origin));
		} catch (ParseException ex) {
			throw new DSSException(ex);
		}
	}

	public X500Name getCrlIssuer() {
		return crlIssuer;
	}

	public Date getCrlIssuedTime() {
		return crlIssuedTime;
	}

	public BigInteger getCrlNumber() {
		return crlNumber;
	}
	
	@Override
	public String toString() {
		return "CRL Reference with Digest [" + super.toString() + "]";
	}

}
