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
package eu.europa.esig.dss.cades.validation;

import java.io.IOException;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;

public class MockDataLoader extends CommonsDataLoader {

	private static final long serialVersionUID = -8743201861357700742L;

	public MockDataLoader() {
	}

	@Override
	public byte[] get(final String urlString) {
		if (urlString.equals("https://sede.060.gob.es/politica_de_firma_anexo_1.pdf")) {
			DSSDocument document = new FileDocument("src/test/resources/validation/dss-728/politica_de_firma_anexo_1.pdf");
			try {
				return Utils.toByteArray(document.openStream());
			} catch (IOException e) {
				throw new DSSException(e);
			}
		} else {
			return super.get(urlString);
		}
	}
}
