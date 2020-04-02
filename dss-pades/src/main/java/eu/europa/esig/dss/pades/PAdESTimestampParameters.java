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
package eu.europa.esig.dss.pades;

import java.util.Date;

import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.pdf.PAdESConstants;

@SuppressWarnings("serial")
public class PAdESTimestampParameters extends CAdESTimestampParameters implements PAdESCommonParameters {
	
	/**
	 * Date of the timestamp
	 */
	protected Date timestampDate = new Date();
	
	/**
	 * This attribute used to define a field ID where the timestamp must be placed to
	 */
	private String timestampFieldId;
	
	/**
	 * This attribute define a length of a reserved space for the timestamp inside a /Contents attribute
	 * 
	 * Default value is 9472 (from PDFBox)
	 */
	private int timestampSize = 9472;

	/**
	 * This attribute allows to override the used Filter for a Timestamp.
	 * 
	 * Default value is Adobe.PPKLite
	 */
	private String timestampFilter = PAdESConstants.TIMESTAMP_DEFAULT_FILTER;

	/**
	 * This attribute allows to override the used subFilter for a Timestamp.
	 * 
	 * Default value is ETSI.RFC3161
	 */
	private String timestampSubFilter = PAdESConstants.TIMESTAMP_DEFAULT_SUBFILTER;

	/**
	 * This attribute is used to create a visible timestamp in PAdES form
	 */
	private SignatureImageParameters signatureImageParameters;
	
	public PAdESTimestampParameters() {
	}
	
	public PAdESTimestampParameters(DigestAlgorithm digestAlgorithm) {
		super(digestAlgorithm);
	}
	
	public PAdESTimestampParameters(CAdESTimestampParameters cadesTimestampParameters) {
		this(cadesTimestampParameters.getDigestAlgorithm());
	}

	@Override
	public String getFilter() {
		return timestampFilter;
	}

	public void setFilter(String timestampFilter) {
		this.timestampFilter = timestampFilter;
	}

	@Override
	public String getSubFilter() {
		return timestampSubFilter;
	}

	public void setSubFilter(String timestampSubFilter) {
		this.timestampSubFilter = timestampSubFilter;
	}

	@Override
	public SignatureImageParameters getImageParameters() {
		return signatureImageParameters;
	}

	public void setImageParameters(SignatureImageParameters signatureImageParameters) {
		this.signatureImageParameters = signatureImageParameters;
	}

	@Override
	public int getContentSize() {
		return timestampSize;
	}

	/**
	 * This setter allows to reserve more than the default size for a timestamp (9472bytes)
	 */
	public void setContentSize(int timestampSize) {
		this.timestampSize = timestampSize;
	}

	@Override
	public Date getSigningDate() {
		return timestampDate;
	}

	@Override
	public String getFieldId() {
		return timestampFieldId;
	}

	public void setFieldId(String timestampFieldId) {
		this.timestampFieldId = timestampFieldId;
	}

}
