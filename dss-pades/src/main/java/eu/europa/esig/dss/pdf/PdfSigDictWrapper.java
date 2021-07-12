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
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.pades.validation.ByteRange;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;

import java.io.IOException;
import java.util.Date;

/**
 * The default implementation of {@code PdfSignatureDictionary}
 */
public class PdfSigDictWrapper implements PdfSignatureDictionary {

	/** The PDF dictionary */
	private final PdfDict dictionary;

	/** The CMSSignedData */
	private final CMSSignedData cmsSignedData;

	/** The signed ByteRange */
	private final ByteRange byteRange;

	/**
	 * Default constructor
	 *
	 * @param dictionary {@link PdfDict}
	 */
	public PdfSigDictWrapper(PdfDict dictionary) {
		this.dictionary = dictionary;
		this.cmsSignedData = buildCMSSignedData();
		this.byteRange = buildByteRange();
	}

	private CMSSignedData buildCMSSignedData() {
		try {
			return new CMSSignedData(getContents());
		} catch (CMSException e) {
			throw new DSSException("Unable to build an instance of CMSSignedData", e);
		}
	}

	private ByteRange buildByteRange() {
		PdfArray byteRangeArray = dictionary.getAsArray("ByteRange");
		if (byteRangeArray == null) {
			throw new DSSException("Unable to retrieve the ByteRange");
		}

		int arraySize = byteRangeArray.size();
		int[] result = new int[arraySize];
		for (int i = 0; i < arraySize; i++) {
			try {
				result[i] = byteRangeArray.getInt(i);
			} catch (IOException e) {
				throw new DSSException("Unable to parse integer from the ByteRange", e);
			}
		}
		return new ByteRange(result);
	}

	@Override
	public String getSignerName() {
		return dictionary.getStringValue("Name");
	}

	@Override
	public String getContactInfo() {
		return dictionary.getStringValue("ContactInfo");
	}

	@Override
	public String getReason() {
		return dictionary.getStringValue("Reason");
	}

	@Override
	public String getLocation() {
		return dictionary.getStringValue("Location");
	}

	@Override
	public Date getSigningDate() {
		return dictionary.getDateValue("M");
	}

	@Override
	public String getType() {
		return dictionary.getNameValue("Type");
	}

	@Override
	public String getFilter() {
		return dictionary.getNameValue("Filter");
	}

	@Override
	public String getSubFilter() {
		return dictionary.getNameValue("SubFilter");
	}

	@Override
	public CMSSignedData getCMSSignedData() {
		return cmsSignedData;
	}

	@Override
	public byte[] getContents() {
		try {
			return dictionary.getBinariesValue("Contents");
		} catch (IOException e) {
			throw new DSSException("Unable to retrieve the signature content", e);
		}
	}

	@Override
	public ByteRange getByteRange() {
		return byteRange;
	}

}
