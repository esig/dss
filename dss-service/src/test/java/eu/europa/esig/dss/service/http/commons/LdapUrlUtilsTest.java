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
package eu.europa.esig.dss.service.http.commons;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LdapUrlUtilsTest {
	
	@Test
	void test() {
		assertEquals("ldap://crl-source.hn/o=Hello", LdapURLUtils.encode("ldap://crl-source.hn/o=Hello"));
	    assertEquals("ldap://crl-source.hn/o=#%20Hello", LdapURLUtils.encode("ldap://crl-source.hn/o=# Hello"));
	    assertEquals("ldap://crl-source.hn/o=%20Hello", LdapURLUtils.encode("ldap://crl-source.hn/o= Hello"));
	    assertEquals("ldap://crl-source.hn/o=Hello%20", LdapURLUtils.encode("ldap://crl-source.hn/o=Hello "));
	    assertEquals("ldap://crl-source.hn/o=%20%20%20", LdapURLUtils.encode("ldap://crl-source.hn/o=   "));
	    assertEquals("ldap://crl-source.hn/o=Hello%20+%20World;", LdapURLUtils.encode("ldap://crl-source.hn/o=Hello + World;"));
	    assertEquals("ldap://crl-source.hn/o=Hello%20+%20World;", LdapURLUtils.encode("ldap://crl-source.hn/o=Hello%20+%20World;"));
	    assertEquals("ldap://ep.nbusr.sk/cn%3dKCA%20NBU%20SR%203,ou%3dSIBEP,o%3dNarodny%20bezpecnostny%20urad,l%3dBratislava,c%3dSK?certificateRevocationList", 
	    		LdapURLUtils.encode("ldap://ep.nbusr.sk/cn%3dKCA%20NBU%20SR%203,ou%3dSIBEP,o%3dNarodny%20bezpecnostny%20urad,l%3dBratislava,c%3dSK?certificateRevocationList"));
	    assertEquals("ldap:///cn%3dKCA%20NBU%20SR%203,ou%3dSIBEP,o%3dNarodny%20bezpecnostny%20urad,l%3dBratislava,c%3dSK?certificateRevocationList", 
	    		LdapURLUtils.encode("ldap:///cn%3dKCA%20NBU%20SR%203,ou%3dSIBEP,o%3dNarodny%20bezpecnostny%20urad,l%3dBratislava,c%3dSK?certificateRevocationList"));
	}

}
