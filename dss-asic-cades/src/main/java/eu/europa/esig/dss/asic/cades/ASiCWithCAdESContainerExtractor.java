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
package eu.europa.esig.dss.asic.cades;

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.model.DSSDocument;

public class ASiCWithCAdESContainerExtractor extends AbstractASiCContainerExtractor {

	public ASiCWithCAdESContainerExtractor(DSSDocument archive) {
		super(archive);
	}

	@Override
	protected boolean isAllowedManifest(String entryName) {
		return entryName.startsWith(ASiCUtils.META_INF_FOLDER) && entryName.contains(ASiCUtils.ASIC_MANIFEST_FILENAME)
				&& entryName.endsWith(ASiCUtils.XML_EXTENSION);
	}

	@Override
	protected boolean isAllowedArchiveManifest(String entryName) {
		return entryName.startsWith(ASiCUtils.META_INF_FOLDER) && ASiCUtils.isArchiveManifest(entryName);
	}

	@Override
	protected boolean isAllowedTimestamp(String entryName) {
		return entryName.startsWith(ASiCUtils.META_INF_FOLDER) && entryName.contains(ASiCUtils.TIMESTAMP_FILENAME)
				&& entryName.endsWith(ASiCUtils.TST_EXTENSION);
	}

	@Override
	protected boolean isAllowedSignature(String entryName) {
		return ASiCUtils.isCAdES(entryName);
	}

}
