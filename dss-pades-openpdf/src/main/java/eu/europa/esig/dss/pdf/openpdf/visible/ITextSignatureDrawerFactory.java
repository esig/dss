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
package eu.europa.esig.dss.pdf.openpdf.visible;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.visible.SignatureDrawerFactory;

public class ITextSignatureDrawerFactory implements SignatureDrawerFactory {

	@Override
	public ITextSignatureDrawer getSignatureDrawer(SignatureImageParameters imageParameters) {
		final DSSDocument image = imageParameters.getImage();
		final SignatureImageTextParameters textParameters = imageParameters.getTextParameters();

		if ((image == null) && (textParameters != null)) {
			return new TextOnlySignatureDrawer();
		} else if ((image != null) && (textParameters == null)) {
			return new ImageOnlySignatureDrawer();
		} else {
			// Custom drawer(s) can be injected with a new Factory and a custom instance of
			// IPdfObjFactory
			throw new DSSException("Not implemented");
		}
	}

}
