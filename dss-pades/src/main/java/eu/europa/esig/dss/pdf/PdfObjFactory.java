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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;

/**
 * The usage of this interface permit the user to choose the underlying PDF
 * library use to created PDF signatures.
 *
 */
public abstract class PdfObjFactory {

	private static final Logger LOG = LoggerFactory.getLogger(PdfObjFactory.class.getName());

	private static PdfObjFactory INSTANCE;

	public static PdfObjFactory getInstance() {
		if (INSTANCE == null) {
			String factoryClassName = System.getProperty("dss.pdf_obj_factory");
			if (factoryClassName != null) {
				LOG.info("Using '" + factoryClassName + "' as the PDF Object Factory Implementation");
				try {
					@SuppressWarnings("unchecked")
					Class<PdfObjFactory> factoryClass = (Class<PdfObjFactory>) Class.forName(factoryClassName);
					INSTANCE = factoryClass.newInstance();
				} catch (Exception ex) {
					LOG.error("Unable to instantiate a PdfObjFactory (specified class:" + factoryClassName + ") :", ex);
				}
			}
			if (INSTANCE == null) {
				throw new DSSException("No instance found for property dss.pdf_obj_factory : " + factoryClassName);
			}
		}
		return INSTANCE;
	}

	/**
	 * This method allows to set a custom PdfObjFactory (or null to reset to the default behavior)
	 * 
	 * @param instance
	 *            the new instance to be used
	 */
	public static void setInstance(PdfObjFactory instance) {
		if (instance != null) {
			LOG.info("Using '" + instance.getClass() + "' as the PDF Object Factory Implementation");
		} else {
			LOG.info("Reseting the PDF Object Factory Implementation");
		}
		INSTANCE = instance;
	}

	public abstract PDFSignatureService newPAdESSignatureService();

	public abstract PDFTimestampService newTimestampSignatureService();

}