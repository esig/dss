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
package eu.europa.esig.dss.cades.validation;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampValidator;
import eu.europa.esig.dss.x509.TimestampType;

public class CMSTimestampValidator extends CMSDocumentValidator implements TimestampValidator {

	private final TimeStampToken bcToken;
	private final TimestampType type;
	private DSSDocument timestampedData;

	public CMSTimestampValidator(DSSDocument timestamp) {
		this(timestamp, null);
	}

	public CMSTimestampValidator(DSSDocument timestamp, TimestampType type) {
		super(timestamp);
		try {
			this.bcToken = new TimeStampToken(cmsSignedData);
			this.type = type;
		} catch (IOException | TSPException e) {
			throw new DSSException("Unable to parse timestamp", e);
		}
	}

	@Override
	public List<AdvancedSignature> getSignatures() {
		return Collections.emptyList();
	}

	@Override
	public TimestampToken getTimestamp() {
		TimestampToken timestampToken = new TimestampToken(bcToken, type, validationCertPool);
		timestampToken.matchData(DSSUtils.toByteArray(timestampedData));
		return timestampToken;
	}

	@Override
	public void setTimestampedData(DSSDocument timestampedData) {
		this.timestampedData = timestampedData;
	}

}
