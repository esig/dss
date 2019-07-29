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
package eu.europa.esig.dss.pades.validation;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses(value = { ASN1Policy.class, DSS1188.class, DSS1376GetOriginalDoc.class, DSS1420.class, DSS818.class, DSS917.class, PadesWrongDigestAlgo.class,
		PdfPkcs7.class, DSS1443.class, DSS1444.class, DSS1690.class, ArchiveTimestampCoverage.class, ASN1Policy.class, DSS1188.class,
		DSS1376GetOriginalDoc.class, DSS1420.class, DSS818.class, DSS917.class, PadesWrongDigestAlgo.class, PdfPkcs7.class, DSS1443.class, DSS1690.class,
		ArchiveTimestampCoverage.class, SIWA.class })
public class PAdESValidationSuite {

}
