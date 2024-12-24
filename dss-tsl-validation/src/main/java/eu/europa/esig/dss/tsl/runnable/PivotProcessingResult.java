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
package eu.europa.esig.dss.tsl.runnable;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.x509.CertificateSource;

/**
 * This class contains the pivot and its introduced signing certificates for the
 * LOTL or the next pivot
 */
public class PivotProcessingResult {

	/** The pivot document */
	private final DSSDocument pivot;

	/** The certificate source to use */
	private final CertificateSource certificateSource;

	/** The LOTL location */
	private final String lotlLocation;

	/**
	 * Default constructor
	 *
	 * @param pivot {@link DSSDocument}
	 * @param certificateSource {@link CertificateSource}
	 * @param lotlLocation {@link String}
	 */
	public PivotProcessingResult(DSSDocument pivot, CertificateSource certificateSource, String lotlLocation) {
		this.pivot = pivot;
		this.certificateSource = certificateSource;
		this.lotlLocation = lotlLocation;
	}

	/**
	 * Gets the pivot document
	 *
	 * @return {@link DSSDocument}
	 */
	public DSSDocument getPivot() {
		return pivot;
	}

	/**
	 * Gets the certificate source
	 *
	 * @return {@link CertificateSource}
	 */
	public CertificateSource getCertificateSource() {
		return certificateSource;
	}

	/**
	 * Gets LOTL location
	 *
	 * @return {@link String}
	 */
	public String getLotlLocation() {
		return lotlLocation;
	}

}
