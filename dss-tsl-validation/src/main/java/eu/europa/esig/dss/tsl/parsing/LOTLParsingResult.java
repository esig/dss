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
package eu.europa.esig.dss.tsl.parsing;

import eu.europa.esig.dss.model.tsl.OtherTSLPointer;

import java.util.List;

/**
 * Parsed LOTL result
 */
public class LOTLParsingResult extends AbstractParsingResult {

	/** List of LOTL pointers */
	private List<OtherTSLPointer> lotlPointers;

	/** List of TL pointers */
	private List<OtherTSLPointer> tlPointers;

	/** Signing certificate announcement URL */
	private String signingCertificateAnnouncementURL;

	/** List of pivot URLs */
	private List<String> pivotURLs;

	/**
	 * Default constructor
	 */
	public LOTLParsingResult() {
		super();
	}

	/**
	 * Gets LOTL other TSL pointers
	 *
	 * @return a list of {@link OtherTSLPointer}s
	 */
	public List<OtherTSLPointer> getLotlPointers() {
		return lotlPointers;
	}

	/**
	 * Sets LOTL other pointers
	 *
	 * @param lotlPointers a list of {@link OtherTSLPointer}s
	 */
	public void setLotlPointers(List<OtherTSLPointer> lotlPointers) {
		this.lotlPointers = lotlPointers;
	}

	/**
	 * Gets TL other TSL pointers
	 *
	 * @return a list of {@link OtherTSLPointer}s
	 */
	public List<OtherTSLPointer> getTlPointers() {
		return tlPointers;
	}

	/**
	 * Sets TL other pointers
	 *
	 * @param tlPointers a list of {@link OtherTSLPointer}s
	 */
	public void setTlPointers(List<OtherTSLPointer> tlPointers) {
		this.tlPointers = tlPointers;
	}

	/**
	 * Gets signing certificate announcement URL
	 *
	 * @return {@link String}
	 */
	public String getSigningCertificateAnnouncementURL() {
		return signingCertificateAnnouncementURL;
	}

	/**
	 * Sets the signing certificate announcement URL
	 *
	 * @param signingCertificateAnnouncementURL {@link String}
	 */
	public void setSigningCertificateAnnouncementURL(String signingCertificateAnnouncementURL) {
		this.signingCertificateAnnouncementURL = signingCertificateAnnouncementURL;
	}

	/**
	 * Gets pivot URLs
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getPivotURLs() {
		return pivotURLs;
	}

	/**
	 * Sets pivot URLs
	 *
	 * @param pivotURLs a list of {@link String}s
	 */
	public void setPivotURLs(List<String> pivotURLs) {
		this.pivotURLs = pivotURLs;
	}

}
