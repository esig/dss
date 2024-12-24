/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.text.ParseException;
import java.util.Date;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.ws.signature.soap.client.DateAdapter;

class DateAdapterTest {

	private DateAdapter adapter = new DateAdapter();

	@Test
	void dateAdapter() throws Exception {
		Date date = new Date();
		assertEquals(adapter.marshal(date), adapter.marshal(adapter.unmarshal(adapter.marshal(date))));
	}

	@Test
	void marshallNull() throws Exception {
		assertThrows(NullPointerException.class, () -> adapter.marshal(null));
	}

	@Test
	void unmarshallNull() throws Exception {
		assertThrows(NullPointerException.class, () -> adapter.unmarshal(null));
	}

	@Test
	void unmarshallInvalid() throws Exception {
		assertThrows(ParseException.class, () -> adapter.unmarshal("aa"));
	}

	@Test
	void unmarshall() throws Exception {
		assertNotNull(adapter.unmarshal("2017-06-19T13:40:01.555Z"));
	}

}
