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
package eu.europa.esig.dss.asic.cades.signature.manifest;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.DefaultASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.AbstractASiCManifestBuilder;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilter;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilterFactory;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;

/**
 * This class is used to generate the ASiCManifest.xml content (ASiC-E)
 *
 * Sample:
 * 
 * <pre>
 * {@code
 * 		<asic:ASiCManifest xmlns:asic="http://uri.etsi.org/02918/v1.2.1#">
 *			<asic:SigReference MimeType="application/pkcs7-signature" URI="META-INF/signature001.p7s">
 *				<asic:DataObjectReference URI="document.txt">
 *					<DigestMethod xmlns="http://www.w3.org/2000/09/xmldsig#" Algorithm=
"http://www.w3.org/2001/04/xmlenc#sha256"/>
 *					<DigestValue xmlns=
"http://www.w3.org/2000/09/xmldsig#">OuL0HMJE899y+uJtyNnTt5B/gFrrw8adNczI+9w9GDQ=</DigestValue>
 *				</asic:DataObjectReference>
 *			</asic:SigReference>
 *		</asic:ASiCManifest>
 * }
 * </pre>
 */
public abstract class ASiCEWithCAdESManifestBuilder extends AbstractASiCManifestBuilder {

	/**
	 * Defines rules for filename creation for new manifest files.
	 */
	private final ASiCWithCAdESFilenameFactory asicFilenameFactory;

	/**
	 * The default constructor
	 *
	 * @param asicContent {@link ASiCContent} representing container's document structure
	 * @param documentFilename {@link String} filename of the document associated with the manifest
	 * @param digestAlgorithm {@link DigestAlgorithm} to use for reference digest computation
	 */
	protected ASiCEWithCAdESManifestBuilder(final ASiCContent asicContent, final String documentFilename,
											final DigestAlgorithm digestAlgorithm) {
		this(asicContent, documentFilename, digestAlgorithm, new DefaultASiCWithCAdESFilenameFactory());
	}

	/**
	 * Constructor with filename factory
	 *
	 * @param asicContent {@link ASiCContent} representing container's document structure
	 * @param documentFilename {@link String} filename of the document associated with the manifest
	 * @param digestAlgorithm {@link DigestAlgorithm} to use for reference digest computation
	 * @param asicFilenameFactory {@link ASiCWithCAdESFilenameFactory}
	 */
	protected ASiCEWithCAdESManifestBuilder(final ASiCContent asicContent, final String documentFilename,
			final DigestAlgorithm digestAlgorithm, final ASiCWithCAdESFilenameFactory asicFilenameFactory) {
		super(asicContent, documentFilename, digestAlgorithm);
		this.asicFilenameFactory = asicFilenameFactory;
	}

	@Override
	protected ASiCContentDocumentFilter initDefaultAsicContentDocumentFilter() {
		return ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter();
	}

	@Override
	protected String getManifestFilename() {
		return asicFilenameFactory.getManifestFilename(asicContent);
	}

}
