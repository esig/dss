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
package eu.europa.esig.dss.asic.signature.asics;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.utils.Utils;

public abstract class AbstractGetDataToSignASiCS {

	private static final String ZIP_ENTRY_DETACHED_FILE = "detached-file";

	/* In case of multi-files and ASiC-S, we need to create a zip with all files to be signed */
	protected DSSDocument createPackageZip(List<DSSDocument> documents, Date signingDate) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); ZipOutputStream zos = new ZipOutputStream(baos)) {

			for (DSSDocument document : documents) {
				final String documentName = document.getName();
				final String name = documentName != null ? documentName : ZIP_ENTRY_DETACHED_FILE;
				final ZipEntry entryDocument = new ZipEntry(name);
				entryDocument.setTime(signingDate.getTime());
				entryDocument.setMethod(ZipEntry.STORED);
				byte[] byteArray = DSSUtils.toByteArray(document);
				entryDocument.setSize(byteArray.length);
				entryDocument.setCompressedSize(byteArray.length);
				final CRC32 crc = new CRC32();
				crc.update(byteArray);
				entryDocument.setCrc(crc.getValue());
				zos.putNextEntry(entryDocument);
				Utils.write(byteArray, zos);
			}

			zos.finish();

			return new InMemoryDocument(baos.toByteArray(), ASiCUtils.PACKAGE_ZIP);
		} catch (IOException e) {
			throw new DSSException("Unable to create package.zip file", e);
		}
	}

}
