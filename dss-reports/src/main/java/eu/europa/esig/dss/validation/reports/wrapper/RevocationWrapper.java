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
package eu.europa.esig.dss.validation.reports.wrapper;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificate;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.RevocationOriginType;
import eu.europa.esig.dss.validation.RevocationSourceType;

public class RevocationWrapper extends AbstractTokenProxy {

	private final XmlRevocation revocation;

	public RevocationWrapper(XmlRevocation revocation) {
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

	public Date getProductionDate() {
		return revocation.getProductionDate();
	}

	public boolean isStatus() {
		return Utils.isTrue(revocation.isStatus());
	}

	public boolean isAvailable() {
		return Utils.isTrue(revocation.isAvailable());
	}

	public Date getThisUpdate() {
		return revocation.getThisUpdate();
	}

	public Date getNextUpdate() {
		return revocation.getNextUpdate();
	}

	public String getReason() {
		return revocation.getReason();
	}

	public Date getRevocationDate() {
		return revocation.getRevocationDate();
	}

	public Date getExpiredCertsOnCRL() {
		return revocation.getExpiredCertsOnCRL();
	}

	public Date getArchiveCutOff() {
		return revocation.getArchiveCutOff();
	}

	public boolean isCertHashExtensionPresent() {
		return Utils.isTrue(revocation.isCertHashExtensionPresent());
	}

	public boolean isCertHashExtensionMatch() {
		return Utils.isTrue(revocation.isCertHashExtensionMatch());
	}

	public RevocationSourceType getSource() {
		return revocation.getSource();
	}

	public RevocationOriginType getOrigin() {
		return revocation.getOrigin();
	}
	
	/**
	 * Returns true if the Revocation data was obtained from a signature container
	 * @return true if the revocation origin is internal, false otherwise
	 */
	public boolean isInternalRevocationOrigin() {
		return RevocationOriginType.INTERNAL_ATTRIBUTE_REVOCATION_VALUES.equals(getOrigin()) || 
				RevocationOriginType.INTERNAL_REVOCATION_VALUES.equals(getOrigin()) || 
				RevocationOriginType.INTERNAL_TIMESTAMP_REVOCATION_VALUES.equals(getOrigin()) || 
				RevocationOriginType.INTERNAL_DSS.equals(getOrigin()) || 
				RevocationOriginType.INTERNAL_VRI.equals(getOrigin());
	}

	public List<XmlDigestAlgoAndValue> getDigestAlgoAndValues() {
		return revocation.getDigestAlgoAndValues();
	}
	
	public byte[] getBinaries() {
		return revocation.getBase64Encoded();
	}
	
	public boolean isRevoked() {
		return !isStatus() && getRevocationDate() != null;
	}

}
