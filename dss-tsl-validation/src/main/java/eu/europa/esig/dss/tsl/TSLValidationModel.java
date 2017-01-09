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
package eu.europa.esig.dss.tsl;

import java.util.Date;

/**
 * This class is a DTO which contains all results (TSLParser / TSLValidator). Instances of this class are stored in
 * TSLRepository
 */
public class TSLValidationModel {

	private String url;
	private String filepath;
	private String sha256FileContent;

	private boolean lotl;

	private boolean certificateSourceSynchronized;
	private Date loadedDate;

	private TSLParserResult parseResult;
	private TSLValidationResult validationResult;

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getFilepath() {
		return filepath;
	}

	public void setFilepath(String filepath) {
		this.filepath = filepath;
	}

	public String getSha256FileContent() {
		return sha256FileContent;
	}

	public void setSha256FileContent(String sha256FileContent) {
		this.sha256FileContent = sha256FileContent;
	}

	public boolean isLotl() {
		return lotl;
	}

	public void setLotl(boolean lotl) {
		this.lotl = lotl;
	}

	public boolean isCertificateSourceSynchronized() {
		return certificateSourceSynchronized;
	}

	public void setCertificateSourceSynchronized(boolean certificateSourceSynchronized) {
		this.certificateSourceSynchronized = certificateSourceSynchronized;
	}

	public Date getLoadedDate() {
		return loadedDate;
	}

	public void setLoadedDate(Date loadedDate) {
		this.loadedDate = loadedDate;
	}

	public TSLParserResult getParseResult() {
		return parseResult;
	}

	public void setParseResult(TSLParserResult parseResult) {
		this.parseResult = parseResult;
	}

	public TSLValidationResult getValidationResult() {
		return validationResult;
	}

	public void setValidationResult(TSLValidationResult validationResult) {
		this.validationResult = validationResult;
	}

}
