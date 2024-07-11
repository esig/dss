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
package eu.europa.esig.dss.asic.cades.signature.manifest;

import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESUtils;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.AbstractASiCManifestBuilder;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilter;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilterFactory;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class is used to generate the ASiCArchiveManifest.xml content (ASiC-E)
 *
 * Sample:
 * 
 * <pre>
 * {@code
 * 		<asic:ASiCManifest xmlns:asic="http://uri.etsi.org/02918/v1.2.1#">
 *			<asic:SigReference URI="META-INF/archive_timestamp.tst" MimeType="application/vnd.etsi.timestamp-token"/>
 *			<asic:DataObjectReference URI="META-INF/signature.p7s" MimeType="application/x-pkcs7-signature">
 *				<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
 *				<DigestValue>3Qeos8...</DigestValue>
 *			</asic:DataObjectReference>
 *			<asic:DataObjectReference URI="toBeSigned.txt" MimeType="text/plain">
 *				<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/> 
 *				<DigestValue>JJZt...</DigestValue>
 *			</asic:DataObjectReference>
 *			<asic:DataObjectReference URI="META-INF/ASiCManifest_1.xml" MimeType="text/xml">
 *				<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
 *				<DigestValue>g5dY...</DigestValue>
 *			</asic:DataObjectReference>
 * 		</asic:ASiCManifest>
 * }
 * </pre>
 */
public class ASiCEWithCAdESArchiveManifestBuilder extends AbstractASiCManifestBuilder {

	/** The "ASiCArchiveManifest.xml" document (root manifest) */
	private final DSSDocument lastArchiveManifest;

	/**
	 * The default constructor
	 *
	 * @param asicContent {@link ASiCContent}
	 * @param lastArchiveManifest {@link DSSDocument} the last archive manifest "ASiCArchiveManifest.xml"
	 * @param digestAlgorithm {@link DigestAlgorithm} to use for digest calculation
	 * @param timestampFilename {@link String} the filename of the timestamp to be associated with the archive manifest
	 */
	public ASiCEWithCAdESArchiveManifestBuilder(final ASiCContent asicContent, final DSSDocument lastArchiveManifest,
												final DigestAlgorithm digestAlgorithm, final String timestampFilename) {
		super(asicContent, timestampFilename, digestAlgorithm);
		this.lastArchiveManifest = lastArchiveManifest;
	}

	@Override
	protected boolean isRootfile(DSSDocument document) {
		return lastArchiveManifest == document;
	}

	@Override
	protected MimeType getSigReferenceMimeType() {
		return MimeTypeEnum.TST;
	}

	@Override
	protected ASiCContentDocumentFilter initDefaultAsicContentDocumentFilter() {
		return ASiCContentDocumentFilterFactory.archiveDocumentsFilter();
	}

	@Override
	public ASiCEWithCAdESArchiveManifestBuilder setAsicContentDocumentFilter(ASiCContentDocumentFilter asicContentDocumentFilter) {
		return (ASiCEWithCAdESArchiveManifestBuilder) super.setAsicContentDocumentFilter(asicContentDocumentFilter);
	}

	@Override
	protected String getManifestFilename() {
		return ASiCWithCAdESUtils.DEFAULT_ARCHIVE_MANIFEST_FILENAME;
	}

}
