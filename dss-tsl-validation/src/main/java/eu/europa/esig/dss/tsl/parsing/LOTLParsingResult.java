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
package eu.europa.esig.dss.tsl.parsing;

import java.util.List;

import eu.europa.esig.dss.spi.tsl.OtherTSLPointer;

public class LOTLParsingResult extends AbstractParsingResult {

	private List<OtherTSLPointer> lotlPointers;
	private List<OtherTSLPointer> tlPointers;

	private String signingCertificateAnnouncementURL;
	private List<String> pivotURLs;
	
	public LOTLParsingResult() {
		super();
	}
	
	public List<OtherTSLPointer> getLotlPointers() {
		return lotlPointers;
	}

	public void setLotlPointers(List<OtherTSLPointer> lotlPointers) {
		this.lotlPointers = lotlPointers;
	}

	public List<OtherTSLPointer> getTlPointers() {
		return tlPointers;
	}

	public void setTlPointers(List<OtherTSLPointer> tlPointers) {
		this.tlPointers = tlPointers;
	}

	public String getSigningCertificateAnnouncementURL() {
		return signingCertificateAnnouncementURL;
	}

	public void setSigningCertificateAnnouncementURL(String signingCertificateAnnouncementURL) {
		this.signingCertificateAnnouncementURL = signingCertificateAnnouncementURL;
	}

	public List<String> getPivotURLs() {
		return pivotURLs;
	}

	public void setPivotURLs(List<String> pivotURLs) {
		this.pivotURLs = pivotURLs;
	}

}
