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
 * Implementation of IPdfObjFactory which looks for in the registered services and uses the first found instance.
 * 
 * This class is not registered as service.
 */
public class ServiceLoaderPdfObjFactory implements IPdfObjFactory {

	private static final Logger LOG = LoggerFactory.getLogger(ServiceLoaderPdfObjFactory.class);

	@Override
	public PDFSignatureService newPAdESSignatureService() {
		return getIPdfObjFactory().newPAdESSignatureService();
	}

	@Override
	public PDFSignatureService newContentTimestampService() {
		return getIPdfObjFactory().newContentTimestampService();
	}

	@Override
	public PDFSignatureService newSignatureTimestampService() {
		return getIPdfObjFactory().newSignatureTimestampService();
	}

	@Override
	public PDFSignatureService newArchiveTimestampService() {
		return getIPdfObjFactory().newArchiveTimestampService();
	}

	private IPdfObjFactory getIPdfObjFactory() {
		ServiceLoader<IPdfObjFactory> loader = ServiceLoader.load(IPdfObjFactory.class);
		Iterator<IPdfObjFactory> iterator = loader.iterator();
		if (!iterator.hasNext()) {
			throw new ExceptionInInitializerError(
					"No implementation found for IPdfObjFactory in classpath, please choose between modules 'dss-pades-pdfbox' or 'dss-pades-openpdf'");
		}
		IPdfObjFactory instance = iterator.next();
		LOG.debug("Current instance of IPdfObjFactory : {}", instance.getClass().getSimpleName());
		return instance;
	}

}
