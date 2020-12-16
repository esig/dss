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
package eu.europa.esig.dss.asic.common.signature.asics;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.model.DSSDocument;

public abstract class AbstractGetDataToSignASiCS {

	/* In case of multi-files and ASiC-S, we need to create a zip with all files to be signed */
	protected DSSDocument createPackageZip(List<DSSDocument> documents, Date signingDate, String zipComment) {
		DSSDocument packageZip = ZipUtils.getInstance().createZipArchive(documents, signingDate, zipComment);
		packageZip.setName(ASiCUtils.PACKAGE_ZIP);
		return packageZip;
	}

}
