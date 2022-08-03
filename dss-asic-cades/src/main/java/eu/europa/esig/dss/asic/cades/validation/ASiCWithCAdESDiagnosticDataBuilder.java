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
package eu.europa.esig.dss.asic.cades.validation;

import eu.europa.esig.dss.asic.common.validation.ASiCContainerDiagnosticDataBuilder;
import eu.europa.esig.dss.cades.validation.CAdESDiagnosticDataBuilder;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.validation.AdvancedSignature;

/**
 * The DiagnosticData builder for an ASiC with CAdES container
 */
public class ASiCWithCAdESDiagnosticDataBuilder extends ASiCContainerDiagnosticDataBuilder {

	/**
	 * Default constructor
	 */
	public ASiCWithCAdESDiagnosticDataBuilder() {
		// empty
	}

	@Override
	public XmlSignature buildDetachedXmlSignature(AdvancedSignature signature) {
		CAdESDiagnosticDataBuilder cadesDiagnosticDataBuilder = new CAdESDiagnosticDataBuilder();
		cadesDiagnosticDataBuilder.tokenExtractionStrategy(tokenExtractionStrategy)
				.tokenIdentifierProvider(identifierProvider);
		return cadesDiagnosticDataBuilder.buildDetachedXmlSignature(signature);
	}

}
