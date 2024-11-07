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
package eu.europa.esig.dss.tsl.dto.builder;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.tsl.cache.state.CachedEntry;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.dto.DownloadCacheDTO;

import java.util.List;

/**
 * Builds {@code DownloadCacheDTO}
 */
public class DownloadCacheDTOBuilder extends AbstractCacheDTOBuilder<XmlDownloadResult> {

	/**
	 * Default constructor
	 *
	 * @param cachedEntry download cache entry
	 */
	public DownloadCacheDTOBuilder(final CachedEntry<XmlDownloadResult> cachedEntry) {
		super(cachedEntry);
	}
	
	@Override
	public DownloadCacheDTO build() {
		DownloadCacheDTO downloadCacheDTO = new DownloadCacheDTO(super.build());
		if (isResultExist()) {
			downloadCacheDTO.setDocument(getDocument());
			downloadCacheDTO.setSha2ErrorMessages(getSha2ErrorMessages());
		}
		return downloadCacheDTO;
	}

	private DSSDocument getDocument() {
		return getResult().getDSSDocument();
	}

	private List<String> getSha2ErrorMessages() {
		return getResult().getSha2ErrorMessages();
	}

}
