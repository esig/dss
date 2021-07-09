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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;

import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Revocation wrapper containing common revocation information
 *
 */
public class RevocationWrapper extends AbstractTokenProxy {

	/** Wrapped {@code XmlRevocation} */
	private final XmlRevocation revocation;
	
	/**
	 * Default constructor
	 *
	 * @param revocation {@link XmlRevocation}
	 */
	public RevocationWrapper(XmlRevocation revocation) {
		Objects.requireNonNull(revocation, "XMLRevocation cannot be null!");
		this.revocation = revocation;
	}

	@Override
	public String getId() {
		return revocation.getId();
	}

	@Override
	protected XmlBasicSignature getCurrentBasicSignature() {
		return revocation.getBasicSignature();
	}

	@Override
	protected List<XmlChainItem> getCurrentCertificateChain() {
		return revocation.getCertificateChain();
	}

	@Override
	protected XmlSigningCertificate getCurrentSigningCertificate() {
		return revocation.getSigningCertificate();
	}

	/**
	 * Returns FoundCertificatesProxy to access embedded certificates
	 * 
	 * @return {@link FoundCertificatesProxy}
	 */
	@Override
	public FoundCertificatesProxy foundCertificates() {
		return new FoundCertificatesProxy(revocation.getFoundCertificates());
	}

	/**
	 * Returns the revocation data production time
	 *
	 * @return {@link Date}
	 */
	public Date getProductionDate() {
		return revocation.getProductionDate();
	}

	/**
	 * Returns the revocation data ThisUpdate time
	 *
	 * @return {@link Date}
	 */
	public Date getThisUpdate() {
		return revocation.getThisUpdate();
	}

	/**
	 * Returns the revocation data NextUpdate time
	 *
	 * @return {@link Date}
	 */
	public Date getNextUpdate() {
		return revocation.getNextUpdate();
	}

	/**
	 * Returns the expired-certs-on-crl attribute time, when present
	 *
	 * @return {@link Date}
	 */
	public Date getExpiredCertsOnCRL() {
		return revocation.getExpiredCertsOnCRL();
	}

	/**
	 * Returns the archive-cut-off attribute time, when present
	 *
	 * @return {@link Date}
	 */
	public Date getArchiveCutOff() {
		return revocation.getArchiveCutOff();
	}

	/**
	 * Gets if a certHash extension if present
	 *
	 * @return TRUE if certHash extension is present, FALSE otherwise
	 */
	public boolean isCertHashExtensionPresent() {
		return revocation.isCertHashExtensionPresent() != null && revocation.isCertHashExtensionPresent();
	}

	/**
	 * Gets if a certHash extension matches to the hash of the concerned certificate
	 *
	 * @return TRUE if certHash matches, FALSE otherwise
	 */
	public boolean isCertHashExtensionMatch() {
		return revocation.isCertHashExtensionMatch() != null && revocation.isCertHashExtensionMatch();
	}

	/**
	 * Returns the origin of the revocation token
	 *
	 * @return {@link RevocationOrigin}
	 */
	public RevocationOrigin getOrigin() {
		return revocation.getOrigin();
	}

	/**
	 * Returns the revocation data type
	 *
	 * @return {@link RevocationType}
	 */
	public RevocationType getRevocationType() {
		return revocation.getType();
	}
	
	@Override
	public byte[] getBinaries() {
		return revocation.getBase64Encoded();
	}
	
	/**
	 * Returns the digest of the revocation token
	 *
	 * @return {@link XmlDigestAlgoAndValue}
	 */
	public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
		return revocation.getDigestAlgoAndValue();
	}
	
	/**
	 * Returns true if the Revocation data was obtained from a signature container
	 *
	 * @return true if the revocation origin is internal, false otherwise
	 */
	public boolean isInternalRevocationOrigin() {
		RevocationOrigin originType = getOrigin();
		if (originType != null) {
			return getOrigin().isInternalOrigin();
		}
		return false;
	}

	/**
	 * Returns the remote URI used to obtain the revocation data
	 *
	 * @return {@link String}
	 */
	public String getSourceAddress() {
		return revocation.getSourceAddress();
	}

}
