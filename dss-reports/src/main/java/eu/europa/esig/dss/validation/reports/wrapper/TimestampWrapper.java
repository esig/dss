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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestamp;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedObject;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedRevocationData;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedTimestamp;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.TimestampType;

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

	public TimestampType getType() {
		return TimestampType.valueOf(timestamp.getType().name());
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

	/**
	 * Returns a complete list of all {@link XmlTimestampedObject}s covered by the timestamp
	 * @return list of {@link XmlTimestampedObject}s
	 */
	public List<XmlTimestampedObject> getTimestampedObjects() {
		return timestamp.getTimestampedObjects();
	}
	
	public XmlTimestampedSignature getLastTimestampedSignature() {
		List<XmlTimestampedSignature> signatures = getTimestampedSignatures();
		if (Utils.isCollectionNotEmpty(signatures)) {
			return signatures.get(signatures.size() - 1);
		}
		return null;
	}
	
	/**
	 * Returns a list of {@link XmlTimestampedSignature}s covered be the current timestamp
	 * @return list of {@link XmlTimestampedSignature}s
	 */
	public List<XmlTimestampedSignature> getTimestampedSignatures() {
		List<XmlTimestampedSignature> timestampedObjectIds = new ArrayList<XmlTimestampedSignature>();
		for (XmlTimestampedObject timestampedObject : getTimestampedObjects()) {
			if (timestampedObject instanceof XmlTimestampedSignature) {
				XmlTimestampedSignature timestampedSignature = (XmlTimestampedSignature) timestampedObject;
				timestampedObjectIds.add(timestampedSignature);
			}
		}
		return timestampedObjectIds;
	}
	
	/**
	 * Returns a list of {@link XmlTimestampedCertificate} ids covered be the current timestamp
	 * @return list of ids
	 */
	public List<String> getTimestampedCertificateIds() {
		List<String> timestampedObjectIds = new ArrayList<String>();
		for (XmlTimestampedObject timestampedObject : getTimestampedObjects()) {
			if (timestampedObject instanceof XmlTimestampedCertificate) {
				XmlTimestampedCertificate timestampedCertificate = (XmlTimestampedCertificate) timestampedObject;
				timestampedObjectIds.add(timestampedCertificate.getCertificate().getId());
			}
		}
		return timestampedObjectIds;
	}
	
	/**
	 * Returns a list of {@link XmlTimestampedRevocationData} ids covered be the current timestamp
	 * @return list of ids
	 */
	public List<String> getTimestampedRevocationIds() {
		List<String> timestampedObjectIds = new ArrayList<String>();
		for (XmlTimestampedObject timestampedObject : getTimestampedObjects()) {
			if (timestampedObject instanceof XmlTimestampedRevocationData) {
				XmlTimestampedRevocationData timestampedRevocation = (XmlTimestampedRevocationData) timestampedObject;
				timestampedObjectIds.add(timestampedRevocation.getRevocation().getId());
			}
		}
		return timestampedObjectIds;
	}
	
	/**
	 * Returns a list of {@link XmlTimestampedTimestamp} ids covered be the current timestamp
	 * @return list of ids
	 */
	public List<String> getTimestampedTimestampIds() {
		List<String> timestampedObjectIds = new ArrayList<String>();
		for (XmlTimestampedObject timestampedObject : getTimestampedObjects()) {
			if (timestampedObject instanceof XmlTimestampedTimestamp) {
				XmlTimestampedTimestamp timestampedTimestamp = (XmlTimestampedTimestamp) timestampedObject;
				timestampedObjectIds.add(timestampedTimestamp.getTimestamp().getId());
			}
		}
		return timestampedObjectIds;
	}
	
	public byte[] getBinaries() {
		return timestamp.getBase64Encoded();
	}
	
	public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
		return timestamp.getDigestAlgoAndValue();
	}

}
