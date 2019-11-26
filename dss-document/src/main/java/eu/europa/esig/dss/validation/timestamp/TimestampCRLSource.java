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
package eu.europa.esig.dss.validation.timestamp;

import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.validation.CMSCRLSource;

/**
 * CRLSource that retrieves information embedded to a {@link TimeStampToken}
 *
 */
@SuppressWarnings("serial")
public class TimestampCRLSource extends CMSCRLSource {

	TimestampCRLSource(TimestampToken timeStampToken) {
		super(timeStampToken.getTimeStamp().toCMSSignedData(), timeStampToken.getUnsignedAttributes());
	}

	@Override
	protected RevocationOrigin getCMSSignedDataRevocationOrigin() {
		return RevocationOrigin.TIMESTAMP_SIGNED_DATA;
	}

	@Override
	protected RevocationOrigin getRevocationValuesOrigin() {
		return RevocationOrigin.TIMESTAMP_REVOCATION_VALUES;
	}

	@Override
	protected RevocationRefOrigin getCompleteRevocationRefsOrigin() {
		return RevocationRefOrigin.TIMESTAMP_REVOCATION_REFS;
	}

	@Override
	protected RevocationRefOrigin getAttributeRevocationRefsOrigin() {
		return RevocationRefOrigin.TIMESTAMP_REVOCATION_REFS;
	}

}
