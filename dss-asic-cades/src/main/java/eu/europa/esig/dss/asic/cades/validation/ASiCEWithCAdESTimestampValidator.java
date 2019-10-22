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
package eu.europa.esig.dss.asic.cades.validation;

import eu.europa.esig.dss.cades.validation.CMSTimestampValidator;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public class ASiCEWithCAdESTimestampValidator extends CMSTimestampValidator {

	/* ASiCArchiveManifest */
	private final ManifestFile manifestFile;

	public ASiCEWithCAdESTimestampValidator(DSSDocument timestamp, TimestampType type, ManifestFile manifestFile, 
			CertificatePool certificatePool) {
		super(timestamp, type);
		this.manifestFile = manifestFile;
		this.validationCertPool = certificatePool;
	}

	/**
	 * Returns the covered {@code ManifestFile}
	 * @return {@link ManifestFile}
	 */
	public ManifestFile getCoveredManifest() {
		return manifestFile;
	}
	
	@Override
	public TimestampToken getTimestamp() {
		TimestampToken timestamp = super.getTimestamp();
		timestamp.setManifestFile(getCoveredManifest());
		return timestamp;
	}

}
