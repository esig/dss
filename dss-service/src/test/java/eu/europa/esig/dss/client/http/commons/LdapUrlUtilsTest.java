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
	}

}
