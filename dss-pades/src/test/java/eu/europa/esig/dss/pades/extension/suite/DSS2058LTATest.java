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
package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.pki.x509.tsp.PKITSPSource;
import eu.europa.esig.dss.spi.x509.tsp.CompositeTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import org.junit.jupiter.api.Tag;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.extension.suite.dss2058.AbstractDSS2058;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Tag("slow")
public class DSS2058LTATest extends AbstractDSS2058 {

	@Override
	protected DSSDocument getDocumentToExtend() {
		return new InMemoryDocument(DSS2058LTATest.class.getResourceAsStream("/validation/dss-2058/dss-2058-LTA-test.pdf"));
	}
	@Override
	protected TSPSource getCompositeTsa() {
		CompositeTSPSource composite = new CompositeTSPSource();
		Map<String, TSPSource> tspSources = new HashMap<>();
		tspSources.put(FAIL_GOOD_TSA, getFailPkiTspSource(GOOD_TSA));
		PKITSPSource pKITspSource = getPKITSPSourceByName(GOOD_TSA);
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.MINUTE, 1);
		Date productionTime = cal.getTime();
		pKITspSource.setProductionTime(productionTime);

		tspSources.put(GOOD_TSA, pKITspSource);

		pKITspSource = getPKITSPSourceByName(EE_GOOD_TSA);
		pKITspSource.setProductionTime(productionTime);

		tspSources.put(EE_GOOD_TSA, pKITspSource);

		composite.setTspSources(tspSources);
		return composite;
	}
}
