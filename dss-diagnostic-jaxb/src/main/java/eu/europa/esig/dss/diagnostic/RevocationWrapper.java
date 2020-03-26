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

import java.util.Date;
import java.util.List;
import java.util.Objects;

import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;

/**
 * Revocation wrapper containing common revocation information
 */
public class RevocationWrapper extends AbstractTokenProxy {

	private final XmlRevocation revocation;
	
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

	public Date getProductionDate() {
		return revocation.getProductionDate();
	}

	public Date getThisUpdate() {
		return revocation.getThisUpdate();
	}

	public Date getNextUpdate() {
		return revocation.getNextUpdate();
	}

	public Date getExpiredCertsOnCRL() {
		return revocation.getExpiredCertsOnCRL();
	}

	public Date getArchiveCutOff() {
		return revocation.getArchiveCutOff();
	}

	public boolean isCertHashExtensionPresent() {
		return revocation.isCertHashExtensionPresent() != null && revocation.isCertHashExtensionPresent();
	}

	public boolean isCertHashExtensionMatch() {
		return revocation.isCertHashExtensionMatch() != null && revocation.isCertHashExtensionMatch();
	}

	public RevocationOrigin getOrigin() {
		return revocation.getOrigin();
	}

	public RevocationType getRevocationType() {
		return revocation.getType();
	}
	
	@Override
	public byte[] getBinaries() {
		return revocation.getBase64Encoded();
	}
	
	public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
		return revocation.getDigestAlgoAndValue();
	}
	
	/**
	 * Returns true if the Revocation data was obtained from a signature container
	 * @return true if the revocation origin is internal, false otherwise
	 */
	public boolean isInternalRevocationOrigin() {
		RevocationOrigin originType = getOrigin();
		if (originType != null) {
			return getOrigin().isInternalOrigin();
		}
		return false;
	}

	public String getSourceAddress() {
		return revocation.getSourceAddress();
	}

}
