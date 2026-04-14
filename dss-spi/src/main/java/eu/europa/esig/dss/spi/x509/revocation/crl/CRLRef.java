/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.x509.revocation.crl;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import org.bouncycastle.asn1.esf.CrlIdentifier;
import org.bouncycastle.asn1.esf.CrlValidatedID;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.util.Date;
import java.util.Objects;

/**
 * Reference to a X509CRL
 *
 */
public final class CRLRef extends RevocationRef<CRL> {

	private static final long serialVersionUID = -6785644604097791548L;

	/** Name of the CRL issuer */
	private X500Principal crlIssuer;

	/** The time of CRL production */
	private Date crlIssueTime;

	/** CRL number */
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
	 * @param digest {@link Digest}
	 * @param crlIssuer {@link X500Principal}
	 * @param crlIssueTime {@link Date}
	 */
	public CRLRef(Digest digest, X500Principal crlIssuer, Date crlIssueTime) {
		this.digest = digest;
		this.crlIssuer = crlIssuer;
		this.crlIssueTime = crlIssueTime;
	}

	/**
	 * The default constructor for CRLRef.
	 *
	 * @param digest {@link Digest}
	 * @param crlIssuer {@link X500Principal}
	 * @param crlIssueTime {@link Date}
	 * @param crlNumber {@link BigInteger}
	 */
	public CRLRef(Digest digest, X500Principal crlIssuer, Date crlIssueTime, BigInteger crlNumber) {
		this.digest = digest;
		this.crlIssuer = crlIssuer;
		this.crlIssueTime = crlIssueTime;
		this.crlNumber = crlNumber;
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
				this.crlIssuer = DSSASN1Utils.toX500Principal(crlIdentifier.getCrlIssuer());
				this.crlIssueTime = crlIdentifier.getCrlIssuedTime().getDate();
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
	 * @return {@link X500Principal}
	 */
	public X500Principal getCrlIssuer() {
		return crlIssuer;
	}

	/**
	 * Gets CRL Issue time
	 *
	 * @return {@link Date}
	 */
	public Date getCrlIssueTime() {
		return crlIssueTime;
	}

	/**
	 * Gets CRL number
	 *
	 * @return {@link BigInteger}
	 */
	public BigInteger getCrlNumber() {
		return crlNumber;
	}

	@Override
	public String toString() {
		return "CRLRef [" +
				"crlIssuer=" + crlIssuer +
				", crlIssueTime=" + crlIssueTime +
				", crlNumber=" + crlNumber +
				"] " + super.toString();
	}

	@Override
	public boolean equals(Object object) {
		if (this == object) return true;
		if (object == null || getClass() != object.getClass()) return false;
		if (!super.equals(object)) return false;

		CRLRef crlRef = (CRLRef) object;
		return Objects.equals(crlIssuer, crlRef.crlIssuer)
				&& Objects.equals(crlIssueTime, crlRef.crlIssueTime)
				&& Objects.equals(crlNumber, crlRef.crlNumber);
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = 31 * result + Objects.hashCode(crlIssuer);
		result = 31 * result + Objects.hashCode(crlIssueTime);
		result = 31 * result + Objects.hashCode(crlNumber);
		return result;
	}

}
