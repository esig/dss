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
package eu.europa.esig.dss.pdf;

import java.util.Iterator;
import java.util.ServiceLoader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The usage of this interface permit the user to choose the underlying PDF
 * library use to created PDF signatures.
 *
 */
public class PdfObjFactory {

	private static final Logger LOG = LoggerFactory.getLogger(PdfObjFactory.class.getName());

	private static IPdfObjFactory impl;

	static {
		ServiceLoader<IPdfObjFactory> loader = ServiceLoader.load(IPdfObjFactory.class);
		Iterator<IPdfObjFactory> iterator = loader.iterator();
		if (!iterator.hasNext()) {
			throw new ExceptionInInitializerError(
					"No implementation found for IPdfObjFactory in classpath, please choose between dss-pades-pdfbox or dss-pades-openpdf");
		}
		impl = iterator.next();
	}

	/**
	 * This method allows to set a custom IPdfObjFactory (or null to reset to the
	 * default behavior)
	 * 
	 * @param instance
	 *                 the new instance to be used
	 */
	public static void setInstance(IPdfObjFactory instance) {
		if (instance != null) {
			LOG.info("Using '" + instance.getClass() + "' as the PDF Object Factory Implementation");
		} else {
			LOG.info("Reseting the PDF Object Factory Implementation");
		}
		impl = instance;
	}

	public static PDFSignatureService newPAdESSignatureService() {
		return impl.newPAdESSignatureService();
	}

	public static PDFTimestampService newTimestampSignatureService() {
		return impl.newTimestampSignatureService();
	}

}