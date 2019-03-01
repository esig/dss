package eu.europa.esig.dss.client.http.commons;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class LdapUrlUtilsTest {
	
	@Test
	public void test() {
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
