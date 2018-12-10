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

import java.util.Collections;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestamp;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedObject;

public class TimestampWrapper extends AbstractTokenProxy {

	private final XmlTimestamp timestamp;

	public TimestampWrapper(XmlTimestamp timestamp) {
		this.timestamp = timestamp;
	}

	@Override
	public String getId() {
		return timestamp.getId();
	}

	@Override
	protected XmlBasicSignature getCurrentBasicSignature() {
		return timestamp.getBasicSignature();
	}

	@Override
	protected List<XmlChainItem> getCurrentCertificateChain() {
		return timestamp.getCertificateChain();
	}

	@Override
	protected XmlSigningCertificate getCurrentSigningCertificate() {
		return timestamp.getSigningCertificate();
	}

	public String getType() {
		return timestamp.getType();
	}

	public Date getProductionTime() {
		return timestamp.getProductionTime();
	}

	public XmlDigestMatcher getMessageImprint() {
		return timestamp.getDigestMatcher();
	}

	public boolean isMessageImprintDataFound() {
		return getMessageImprint().isDataFound();
	}

	public boolean isMessageImprintDataIntact() {
		return getMessageImprint().isDataIntact();
	}

	@Override
	public List<XmlDigestMatcher> getDigestMatchers() {
		return Collections.singletonList(getMessageImprint());
	}

	public List<XmlTimestampedObject> getTimestampedObjects() {
		return timestamp.getTimestampedObjects();
	}
	
	public byte[] getBinaries() {
		return timestamp.getBase64Encoded();
	}

}
